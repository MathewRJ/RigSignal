use std::borrow::Cow;

/// Make untrusted text safe to place inside one plain-text log line.
pub(crate) fn escape_for_log(s: &str) -> Cow<'_, str> {
    let needs_escape = |c: char| {
        matches!(c, '\\' | '\u{0000}'..='\u{001f}' | '\u{007f}'..='\u{009f}'
            | '\u{200e}' | '\u{200f}' | '\u{202a}'..='\u{202e}'
            | '\u{2028}' | '\u{2029}' | '\u{2066}'..='\u{2069}')
    };
    if !s.chars().any(needs_escape) {
        return Cow::Borrowed(s);
    }
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if needs_escape(c) => out.push_str(&format!("\\u{{{:x}}}", c as u32)),
            c => out.push(c),
        }
    }
    Cow::Owned(out)
}

pub(crate) fn truncate_chars(s: &str, max_bytes: usize) -> &str {
    &s[..s.floor_char_boundary(max_bytes.min(s.len()))]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes_every_log_line_control_class() {
        assert_eq!(escape_for_log("\0\u{1f}"), "\\u{0}\\u{1f}");
        assert_eq!(escape_for_log("\n\r\t"), "\\n\\r\\t");
        assert_eq!(escape_for_log("\u{7f}"), "\\u{7f}");
        assert_eq!(
            escape_for_log("\u{80}\u{85}\u{9f}"),
            "\\u{80}\\u{85}\\u{9f}"
        );
        assert_eq!(escape_for_log("\u{2028}\u{2029}"), "\\u{2028}\\u{2029}");
        assert_eq!(escape_for_log("\u{200e}\u{200f}"), "\\u{200e}\\u{200f}");
        assert_eq!(escape_for_log("\u{202a}\u{202e}"), "\\u{202a}\\u{202e}");
        assert_eq!(escape_for_log("\u{2066}\u{2069}"), "\\u{2066}\\u{2069}");
        assert_eq!(escape_for_log("\\"), "\\\\");
        assert_eq!(escape_for_log("\\n"), "\\\\n");
    }

    #[test]
    fn plain_ascii_is_borrowed_and_truncation_uses_char_boundaries() {
        assert!(matches!(
            escape_for_log("plain ASCII"),
            Cow::Borrowed("plain ASCII")
        ));
        let text = format!("{}é", "a".repeat(199));
        assert_eq!(truncate_chars(&text, 200), "a".repeat(199));
        assert!(truncate_chars(&text, 200).len() <= 200);
        assert_eq!(truncate_chars(&text, 201), text);
    }
}
