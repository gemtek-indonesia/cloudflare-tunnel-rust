use anyhow::{Context, Result, bail};
use regex::Regex;
use regex_syntax::{
    ast::{self, AssertionKind, Ast, ClassPerlKind, ClassSet, ClassSetItem, Flag, FlagsItemKind},
    hir::{ClassUnicode, ClassUnicodeRange},
};
use serde::Deserialize;
use std::{collections::BTreeMap, sync::LazyLock};

#[derive(Deserialize)]
struct Unicode {
    go_toolchain: String,
    unicode_version: String,
    properties: BTreeMap<String, Vec<[u32; 3]>>,
    folds: Vec<Vec<u32>>,
    category_aliases: BTreeMap<String, String>,
}
static UNICODE: LazyLock<Unicode> = LazyLock::new(|| {
    let value: Unicode = serde_json::from_str(include_str!("go_unicode.json"))
        .expect("checked generated Go regexp Unicode metadata");
    assert_eq!(value.go_toolchain, "go1.26.0");
    assert_eq!(value.unicode_version, "15.0.0");
    value
});

pub fn compile(pattern: &str) -> Result<Regex> {
    let normalized = normalize_tokens(pattern)?;
    let mut ast = ast::parse::Parser::new()
        .parse(&normalized)
        .map_err(|_| anyhow::anyhow!("invalid ingress path regular expression"))?;
    let mut insensitive = false;
    rewrite(&mut ast, &mut insensitive)?;
    Regex::new(&ast.to_string())
        .map_err(|_| anyhow::anyhow!("invalid ingress path regular expression"))
}

fn normalize_tokens(pattern: &str) -> Result<String> {
    let mut output = String::new();
    let mut input = pattern.char_indices().peekable();
    let mut in_class = false;
    let mut first = false;
    let mut negated = false;
    let mut capture = 0u32;
    while let Some((index, character)) = input.next() {
        if character == '\\' {
            let (_, escaped) = input.next().context("unfinished regexp escape")?;
            if escaped == 'Q' && !in_class {
                let start = input.peek().map_or(pattern.len(), |(index, _)| *index);
                let end = pattern[start..].find(r"\E").map(|offset| start + offset);
                output.push_str(&regex::escape(
                    &pattern[start..end.unwrap_or(pattern.len())],
                ));
                while input
                    .peek()
                    .is_some_and(|(index, _)| *index < end.map_or(pattern.len(), |end| end + 2))
                {
                    input.next();
                }
            } else if ('0'..='7').contains(&escaped) {
                let mut digits = escaped.to_string();
                for _ in 0..2 {
                    if input
                        .peek()
                        .is_some_and(|(_, value)| ('0'..='7').contains(value))
                    {
                        digits.push(input.next().unwrap().1);
                    } else {
                        break;
                    }
                }
                if escaped != '0' && digits.len() == 1 {
                    bail!("backreferences are not supported by Go regexp");
                }
                output.push_str(&format!(r"\x{{{:x}}}", u32::from_str_radix(&digits, 8)?));
            } else if !escaped.is_ascii_alphanumeric() || escaped == '_' {
                output.push_str(&regex::escape(&escaped.to_string()));
            } else {
                output.push('\\');
                output.push(escaped);
            }
            if in_class {
                first = false;
            }
            continue;
        }
        if in_class {
            if character == '[' && pattern[index..].starts_with("[:") {
                let length = pattern[index..]
                    .find(":]")
                    .context("unfinished POSIX class")?
                    + 2;
                output.push_str(&pattern[index..index + length]);
                while input
                    .peek()
                    .is_some_and(|(position, _)| *position < index + length)
                {
                    input.next();
                }
                first = false;
                continue;
            }
            if character == ']' && !first {
                in_class = false;
            } else if character == '^' && first && !negated {
                negated = true;
                output.push(character);
                continue;
            } else if ['[', ']', '&', '~'].contains(&character) {
                output.push_str(&format!(r"\x{{{:x}}}", character as u32));
                first = false;
                continue;
            }
            first = false;
        } else if character == '[' {
            in_class = true;
            first = true;
            negated = false;
        } else if character == '(' {
            let rest = &pattern[index..];
            let prefix = if rest.starts_with("(?P<") {
                Some(4)
            } else if rest.starts_with("(?<") {
                Some(3)
            } else {
                None
            };
            if let Some(prefix) = prefix {
                let end = rest[prefix..]
                    .find('>')
                    .context("unfinished regexp capture name")?
                    + prefix;
                let name = &rest[prefix..end];
                if name.is_empty()
                    || !name
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
                {
                    bail!("invalid Go regexp capture name");
                }
                // Capture names do not escape this boolean routing matcher.
                output.push_str(&format!("(?P<cloudflared{capture}>"));
                capture += 1;
                while input
                    .peek()
                    .is_some_and(|(position, _)| *position <= index + end)
                {
                    input.next();
                }
                continue;
            }
        }
        output.push(character);
    }
    Ok(output)
}

fn flags(flags: &mut ast::Flags, insensitive: &mut bool) -> Result<()> {
    let mut enabled = true;
    for item in &flags.items {
        match item.kind {
            FlagsItemKind::Negation => enabled = false,
            FlagsItemKind::Flag(Flag::CaseInsensitive) => *insensitive = enabled,
            FlagsItemKind::Flag(Flag::Unicode | Flag::CRLF | Flag::IgnoreWhitespace) => {
                bail!("regular expression flag is not supported by Go regexp");
            }
            _ => {}
        }
    }
    flags
        .items
        .retain(|item| item.kind != FlagsItemKind::Flag(Flag::CaseInsensitive));
    if let Some(position) = flags
        .items
        .iter()
        .position(|item| item.kind == FlagsItemKind::Negation)
        && position + 1 == flags.items.len()
    {
        flags.items.remove(position);
    }
    Ok(())
}

fn rewrite(ast: &mut Ast, insensitive: &mut bool) -> Result<()> {
    match ast {
        Ast::Literal(literal) if *insensitive => {
            *ast = class_ast(fold(singleton(literal.c), true))?;
        }
        Ast::ClassPerl(class) => *ast = class_ast(perl(class, *insensitive))?,
        Ast::ClassUnicode(class) => *ast = class_ast(property(class, *insensitive)?)?,
        Ast::ClassBracketed(class) => {
            let mut set = class_set(&class.kind, *insensitive)?;
            if class.negated {
                set.negate();
            }
            *ast = class_ast(set)?;
        }
        Ast::Assertion(assertion) => match assertion.kind {
            AssertionKind::WordBoundary => *ast = parse(r"(?-u:\b)")?,
            AssertionKind::NotWordBoundary => *ast = parse(r"(?-u:\B)")?,
            AssertionKind::StartLine
            | AssertionKind::EndLine
            | AssertionKind::StartText
            | AssertionKind::EndText => {}
            _ => bail!("word-boundary syntax is not supported by Go regexp"),
        },
        Ast::Flags(set) => {
            flags(&mut set.flags, insensitive)?;
            if set.flags.items.is_empty() {
                *ast = Ast::empty(set.span);
            }
        }
        Ast::Group(group) => {
            let mut scoped = *insensitive;
            if let ast::GroupKind::NonCapturing(value) = &mut group.kind {
                flags(value, &mut scoped)?;
            }
            rewrite(&mut group.ast, &mut scoped)?;
        }
        Ast::Repetition(repetition) => {
            if matches!(repetition.op.kind, ast::RepetitionKind::Range(ast::RepetitionRange::Exactly(value) | ast::RepetitionRange::AtLeast(value)) if value > 1000)
                || matches!(repetition.op.kind, ast::RepetitionKind::Range(ast::RepetitionRange::Bounded(min,max)) if min > 1000 || max > 1000)
            {
                bail!("repetition count exceeds Go regexp maximum");
            }
            rewrite(&mut repetition.ast, insensitive)?;
        }
        Ast::Alternation(alternation) => {
            for child in &mut alternation.asts {
                rewrite(child, insensitive)?;
            }
        }
        Ast::Concat(concatenation) => {
            for child in &mut concatenation.asts {
                rewrite(child, insensitive)?;
            }
        }
        _ => {}
    }
    Ok(())
}
fn parse(pattern: &str) -> Result<Ast> {
    ast::parse::Parser::new()
        .parse(pattern)
        .map_err(|_| anyhow::anyhow!("invalid compatibility expression"))
}
fn singleton(value: char) -> ClassUnicode {
    ClassUnicode::new([ClassUnicodeRange::new(value, value)])
}
fn contains(class: &ClassUnicode, value: char) -> bool {
    let index = class.ranges().partition_point(|range| range.end() < value);
    class
        .ranges()
        .get(index)
        .is_some_and(|range| range.start() <= value)
}
fn fold(mut class: ClassUnicode, insensitive: bool) -> ClassUnicode {
    if insensitive {
        let mut additions = Vec::new();
        for cycle in &UNICODE.folds {
            if cycle
                .iter()
                .filter_map(|value| char::from_u32(*value))
                .any(|value| contains(&class, value))
            {
                additions.extend(
                    cycle
                        .iter()
                        .filter_map(|value| char::from_u32(*value))
                        .map(|value| ClassUnicodeRange::new(value, value)),
                );
            }
        }
        class.union(&ClassUnicode::new(additions));
    }
    class
}
fn perl(class: &ast::ClassPerl, insensitive: bool) -> ClassUnicode {
    let ranges = match class.kind {
        ClassPerlKind::Digit => vec![ClassUnicodeRange::new('0', '9')],
        ClassPerlKind::Space => ['\t', '\n', '\x0c', '\r', ' ']
            .map(|value| ClassUnicodeRange::new(value, value))
            .to_vec(),
        ClassPerlKind::Word => vec![
            ClassUnicodeRange::new('0', '9'),
            ClassUnicodeRange::new('A', 'Z'),
            ClassUnicodeRange::new('a', 'z'),
            ClassUnicodeRange::new('_', '_'),
        ],
    };
    let mut value = fold(ClassUnicode::new(ranges), insensitive);
    if class.negated {
        value.negate();
    }
    value
}
fn property(class: &ast::ClassUnicode, insensitive: bool) -> Result<ClassUnicode> {
    let name = match &class.kind {
        ast::ClassUnicodeKind::OneLetter(value) => value.to_string(),
        ast::ClassUnicodeKind::Named(value) => value.clone(),
        _ => bail!("Unicode named-value syntax is not supported by Go regexp"),
    };
    let (name, inverted) = name
        .strip_prefix('^')
        .map_or((name.as_str(), false), |name| (name, true));
    let canonical = canonical_name(name);
    let name = match canonical.as_str() {
        "Ascii" => "ASCII",
        "Lc" => "LC",
        "Assigned" => "Cn",
        name => name,
    };
    let actual = UNICODE
        .category_aliases
        .iter()
        .find_map(|(alias, actual)| (canonical_name(alias) == canonical).then_some(actual.as_str()))
        .unwrap_or(name);
    let source = UNICODE
        .properties
        .get(actual)
        .context("Unicode property is not supported by Go regexp")?;
    let mut ranges = Vec::new();
    for &[low, high, stride] in source {
        if stride == 1 {
            // Unicode scalar ranges omit surrogates, which cannot occur in decoded URL text.
            for (start, end) in [(low, high.min(0xd7ff)), (low.max(0xe000), high)] {
                if start <= end
                    && let (Some(start), Some(end)) = (char::from_u32(start), char::from_u32(end))
                {
                    ranges.push(ClassUnicodeRange::new(start, end));
                }
            }
        } else {
            ranges.extend(
                (low..=high)
                    .step_by(stride as usize)
                    .filter_map(char::from_u32)
                    .map(|value| ClassUnicodeRange::new(value, value)),
            );
        }
    }
    let mut value = fold(ClassUnicode::new(ranges), insensitive);
    if class.negated != (inverted != (canonical == "Assigned")) {
        value.negate();
    }
    Ok(value)
}
fn canonical_name(name: &str) -> String {
    let mut first = true;
    name.chars()
        .filter(|character| !matches!(character, '_' | '-' | ' '))
        .map(|character| {
            let character = if first {
                character.to_ascii_uppercase()
            } else {
                character.to_ascii_lowercase()
            };
            first = false;
            character
        })
        .collect()
}
fn class_set(set: &ClassSet, insensitive: bool) -> Result<ClassUnicode> {
    match set {
        ClassSet::Item(item) => class_item(item, insensitive),
        ClassSet::BinaryOp(_) => {
            bail!("character-class set operators are not covered by Go regexp compatibility")
        }
    }
}
fn class_item(item: &ClassSetItem, insensitive: bool) -> Result<ClassUnicode> {
    Ok(match item {
        ClassSetItem::Empty(_) => ClassUnicode::new([]),
        ClassSetItem::Literal(literal) => fold(singleton(literal.c), insensitive),
        ClassSetItem::Range(range) => fold(
            ClassUnicode::new([ClassUnicodeRange::new(range.start.c, range.end.c)]),
            insensitive,
        ),
        ClassSetItem::Perl(class) => perl(class, insensitive),
        ClassSetItem::Unicode(class) => property(class, insensitive)?,
        ClassSetItem::Bracketed(class) => {
            let mut value = class_set(&class.kind, insensitive)?;
            if class.negated {
                value.negate();
            }
            value
        }
        ClassSetItem::Union(union) => {
            let mut value = ClassUnicode::new([]);
            for item in &union.items {
                value.union(&class_item(item, insensitive)?);
            }
            value
        }
        ClassSetItem::Ascii(class) => {
            let mut atom = ast::ClassBracketed {
                span: class.span,
                negated: false,
                kind: ClassSet::Item(ClassSetItem::Ascii(class.clone())),
            };
            if class.negated {
                let ClassSet::Item(ClassSetItem::Ascii(value)) = &mut atom.kind else {
                    unreachable!()
                };
                value.negated = false;
            }
            let ast = Ast::class_bracketed(atom);
            let hir = regex_syntax::hir::translate::Translator::new()
                .translate(&ast.to_string(), &ast)?;
            let regex_syntax::hir::HirKind::Class(regex_syntax::hir::Class::Unicode(value)) =
                hir.kind()
            else {
                bail!("invalid ASCII character class");
            };
            let mut value = fold(value.clone(), insensitive);
            if class.negated {
                value.negate();
            }
            value
        }
    })
}
fn class_ast(class: ClassUnicode) -> Result<Ast> {
    if class.ranges().is_empty() {
        return parse(r"[^\x{0}-\x{10ffff}]");
    }
    let mut text = String::from("[");
    for range in class.ranges() {
        text.push_str(&format!(r"\x{{{:x}}}", range.start() as u32));
        if range.start() != range.end() {
            text.push_str(&format!(r"-\x{{{:x}}}", range.end() as u32));
        }
    }
    text.push(']');
    parse(&text)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn ascii_classes_frozen_unicode_and_scoped_fold() {
        for (pattern, positive, negative) in [
            (r"^\d+$", "123", "١٢٣"),
            (r"^\w+$", "abc_1", "é"),
            (r"^\s+$", " \t\r\n", "\u{a0}"),
            (r"\bword\b", "word", "sword"),
        ] {
            let expression = compile(pattern).unwrap();
            assert!(expression.is_match(positive));
            assert!(!expression.is_match(negative));
        }
        assert!(compile(r"^\D+$").unwrap().is_match("١"));
        assert!(!compile(r"^[\d_]+$").unwrap().is_match("١"));
        assert!(compile(r"^.$").unwrap().is_match("é"));
        assert!(compile(r"^\p{Greek}+$").unwrap().is_match("αβ"));
        assert!(!compile(r"^\p{Han}+$").unwrap().is_match("\u{2ebf0}"));
        assert!(compile(r"(?i)^k$").unwrap().is_match("K"));
        assert!(compile(r"(?i:k)(?-i:s)").unwrap().is_match("Ks"));
        assert!(!compile(r"(?i:k)(?-i:s)").unwrap().is_match("KS"));
        assert!(compile(r"(?i)^\w$").unwrap().is_match("ſ"));
        assert!(compile(r"(?P<same>a)(?P<same>b)").unwrap().is_match("ab"));
        assert!(compile(r"(?P<1>a)").unwrap().is_match("a"));
        assert!(compile(r"[a&&b]").unwrap().is_match("&"));
        assert!(compile(r"[a[b]]").unwrap().is_match("[]"));
        assert!(compile(r"\123").unwrap().is_match("S"));
        assert!(compile(r"\777").unwrap().is_match("ǿ"));
        assert!(compile(r"\1").is_err());
        assert!(compile(r"(?x)a").is_err());
        assert!(compile(r"a{1001}").is_err());
        assert!(compile(r"\\d").unwrap().is_match(r"\d"));
    }
}
