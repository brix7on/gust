// Списки доменов: совпадение по самому домену и всем поддоменам.

use std::collections::HashSet;

#[derive(Debug, Default, Clone)]
pub struct HostList {
    set: HashSet<String>,
}

impl HostList {
    pub fn is_empty(&self) -> bool {
        self.set.is_empty()
    }

    pub fn add(&mut self, d: &str) {
        let d = d
            .trim()
            .trim_start_matches("*.")
            .trim_start_matches('.')
            .trim_end_matches('.')
            .to_ascii_lowercase();
        if !d.is_empty() && !d.starts_with('#') {
            self.set.insert(d);
        }
    }

    pub fn load(&mut self, path: &str) -> Result<(), String> {
        let text = std::fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))?;
        for l in text.lines() {
            self.add(l.split('#').next().unwrap_or(""));
        }
        Ok(())
    }

    pub fn matches(&self, host: &str) -> bool {
        let mut h = host.trim_end_matches('.').to_ascii_lowercase();
        loop {
            if self.set.contains(&h) {
                return true;
            }
            match h.find('.') {
                Some(i) => h = h[i + 1..].to_string(),
                None => return false,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn suffix_match() {
        let mut l = HostList::default();
        for d in [
            "discord.com",
            "*.googlevideo.com",
            "# comment",
            "",
            "YouTube.com.",
        ] {
            l.add(d);
        }
        assert!(l.matches("discord.com"));
        assert!(l.matches("gateway.discord.com"));
        assert!(l.matches("rr1---sn-abc.googlevideo.com"));
        assert!(l.matches("www.youtube.com"));
        assert!(!l.matches("notdiscord.com"));
        assert!(!l.matches("com"));
    }
}
