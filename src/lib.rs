//! robots.txt parser for Rust
//!
//! The robots.txt Exclusion Protocol is implemented as specified in
//! <http://www.robotstxt.org/norobots-rfc.txt>.
//!
//! This crate is based on https://github.com/messense/robotparser-rs
//!
//! # Installation
//!
//! Add it to your ``Cargo.toml``:
//!
//! ```toml
//! [dependencies]
//! robotstxt = "0.1"
//! ```
//!
//! # Examples
//!
//! ```rust
//! use robotstxt::RobotFileParser;
//!
//! fn main() {
//!     let parser = RobotFileParser::parse("
//!        User-agent: crawler1\n\
//!        Allow: /not_here/but_here\n\
//!        Disallow:/not_here/\n\
//!     ");
//!     assert!(parser.can_fetch("crawler1", "/not_here/but_here"));
//!     assert!(!parser.can_fetch("crawler1", "/not_here/no_way"));
//! }
//! ```

use std::borrow::Cow;
use std::time::{Duration};

use url::Url;

/// A rule line is a single "Allow:" (allowance==True) or "Disallow:"
/// (allowance==False) followed by a path."""
#[derive(Debug, Eq, PartialEq, Clone)]
struct RuleLine<'a> {
    path: Cow<'a, str>,
    allowance: bool,
}

#[derive(Debug, Eq, PartialEq, Clone)]
pub struct RequestRate {
    pub requests: usize,
    pub seconds: usize,
}

/// An entry has one or more user-agents and zero or more rulelines
#[derive(Debug, Eq, PartialEq, Clone)]
struct Entry<'a> {
    useragents: Vec<String>,
    rulelines: Vec<RuleLine<'a>>,
    crawl_delay: Option<Duration>,
    sitemaps: Vec<Url>,
    req_rate: Option<RequestRate>,
}


impl<'a> RuleLine<'a> {
    fn new<S>(path: S, allowance: bool) -> RuleLine<'a>
        where S: Into<Cow<'a, str>>
    {
        let path = path.into();
        let mut allow = allowance;
        if path == "" && !allowance {
            // an empty value means allow all
            allow = true;
        }
        RuleLine {
            path: path,
            allowance: allow,
        }
    }

    fn applies_to(&self, filename: &str) -> bool {
        self.path == "*" || filename.starts_with(&self.path[..])
    }
}


impl<'a> Entry<'a> {
    fn new() -> Entry<'a> {
        Entry {
            useragents: vec![],
            rulelines: vec![],
            crawl_delay: None,
            sitemaps: Vec::new(),
            req_rate: None,
        }
    }

    /// check if this entry applies to the specified agent
    fn applies_to(&self, useragent: &str) -> bool {
        let ua = useragent.split('/').nth(0).unwrap_or("").to_lowercase();
        let useragents = &self.useragents;
        for agent in &*useragents {
            if agent == "*" {
                return true;
            }
            if ua.contains(agent) {
                return true;
            }
        }
        false
    }


    /// Preconditions:
    /// - our agent applies to this entry
    /// - filename is URL decoded
    fn allowance(&self, filename: &str) -> bool {
        let rulelines = &self.rulelines;
        for line in &*rulelines {
            if line.applies_to(filename) {
                return line.allowance;
            }
        }
        true
    }

    fn push_useragent(&mut self, useragent: &str) {
        self.useragents.push(useragent.to_lowercase().to_owned());
    }

    fn push_ruleline(&mut self, ruleline: RuleLine<'a>) {
        self.rulelines.push(ruleline);
    }

    fn has_useragent(&self, useragent: &str) -> bool {
        let useragents = &self.useragents;
        useragents.contains(&useragent.to_owned())
    }

    fn is_empty(&self) -> bool {
        self.useragents.is_empty() && self.rulelines.is_empty()
    }

    fn set_crawl_delay(&mut self, delay: Duration) {
        self.crawl_delay = Some(delay);
    }

    fn crawl_delay(&self) -> Option<Duration> {
        self.crawl_delay
    }

    fn add_sitemap(&mut self, url: &str) {
        if let Ok(url) = Url::parse(url) {
            self.sitemaps.push(url);
        }
    }

    fn sitemaps(&self) -> &Vec<Url> {
        &self.sitemaps
    }

    fn set_request_rate(&mut self, req_rate: RequestRate) {
        self.req_rate = Some(req_rate);
    }

    fn request_rate(&self) -> Option<RequestRate> {
        self.req_rate.clone()
    }
}


impl<'a> Default for Entry<'a> {
    fn default() -> Entry<'a> {
        Entry::new()
    }
}

/// robots.txt file parser
#[derive(Debug, Eq, PartialEq, Clone)]
pub struct RobotFileParser<'a> {
    entries: Vec<Entry<'a>>,
    default_entry: Entry<'a>,
    disallow_all: bool,
    allow_all: bool,
}


impl<'a> RobotFileParser<'a> {
    fn _add_entry(&mut self, entry: Entry<'a>) {
        if entry.has_useragent("*") {
            // the default entry is considered last
            let default_entry = &mut self.default_entry;
            if default_entry.is_empty() {
                // the first default entry wins
                *default_entry = entry;
            }
        } else {
            let entries = &mut self.entries;
            entries.push(entry);
        }
    }

    ///
    /// Parse the input lines from a robots.txt file
    ///
    /// We allow that a user-agent: line is not preceded by
    /// one or more blank lines.
    ///
    pub fn parse<T: AsRef<str>>(robots_txt: T) -> Self {
        let mut this = RobotFileParser {
            entries: vec![],
            default_entry: Entry::new(),
            disallow_all: false,
            allow_all: false,
        };

        use url::percent_encoding::percent_decode;

        let lines = robots_txt.as_ref().split('\n');

        // states:
        //   0: start state
        //   1: saw user-agent line
        //   2: saw an allow or disallow line
        let mut state = 0;
        let mut entry = Entry::new();

        for mut ln in lines {
            if ln.is_empty() {
                match state {
                    1 => {
                        entry = Entry::new();
                        state = 0;
                    }
                    2 => {
                        this._add_entry(entry);
                        entry = Entry::new();
                        state = 0;
                    }
                    _ => {}
                }
            }
            // remove optional comment and strip line
            if let Some(i) = ln.find('#') {
                ln = &ln[0..i];
            }
            ln = ln.trim();
            if ln.is_empty() {
                continue;
            }
            let parts: Vec<&str> = ln.splitn(2, ':').collect();
            if parts.len() == 2 {
                let part0 = parts[0].trim().to_lowercase();
                let part1 = String::from_utf8(percent_decode(parts[1].trim().as_bytes()).collect())
                    .unwrap_or("".to_owned());
                match part0 {
                    ref x if x == "user-agent" => {
                        if state == 2 {
                            this._add_entry(entry);
                            entry = Entry::new();
                        }
                        entry.push_useragent(&part1);
                        state = 1;
                    }
                    ref x if x == "disallow" => {
                        if state != 0 {
                            entry.push_ruleline(RuleLine::new(part1, false));
                            state = 2;
                        }
                    }
                    ref x if x == "allow" => {
                        if state != 0 {
                            entry.push_ruleline(RuleLine::new(part1, true));
                            state = 2;
                        }
                    }
                    ref x if x == "crawl-delay" => {
                        if state != 0 {
                            if let Ok(delay) = part1.parse::<f64>() {
                                let delay_seconds = delay.trunc();
                                let delay_nanoseconds = delay.fract() * 10f64.powi(9);
                                let delay = Duration::new(delay_seconds as u64, delay_nanoseconds as u32);
                                entry.set_crawl_delay(delay);
                            }
                            state = 2;
                        }
                    }
                    ref x if x == "sitemap" => {
                        if state != 0 {
                            entry.add_sitemap(&part1);
                            state = 2;
                        }
                    }
                    ref x if x == "request-rate" => {
                        if state != 0 {
                            let numbers: Vec<Result<usize, _>> = part1.split('/').map(|x| x.parse::<usize>()).collect();
                            if numbers.len() == 2 && numbers[0].is_ok() && numbers[1].is_ok() {
                                let req_rate = RequestRate {
                                    requests: numbers[0].clone().unwrap(),
                                    seconds: numbers[1].clone().unwrap(),
                                };
                                entry.set_request_rate(req_rate);
                            }
                            state = 2;
                        }
                    }
                    _ => {}
                }
            }
        }
        if state == 2 {
            this._add_entry(entry);
        }

        this
    }

    /// Using the parsed robots.txt decide if useragent can fetch url
    pub fn can_fetch<T: AsRef<str>>(&self, useragent: T, url: T) -> bool {
        use url::percent_encoding::percent_decode;

        let useragent = useragent.as_ref();
        let url = url.as_ref();

        if self.disallow_all {
            return false;
        }
        if self.allow_all {
            return true;
        }
        // search for given user agent matches
        // the first match counts
        let decoded_url = String::from_utf8(percent_decode(url.trim().as_bytes()).collect()).unwrap_or("".to_owned());
        let url_str = match decoded_url {
            ref u if !u.is_empty() => u.to_owned(),
            _ => "/".to_owned(),
        };
        let entries = &self.entries;
        for entry in &*entries {
            if entry.applies_to(useragent) {
                return entry.allowance(&url_str);
            }
        }
        // try the default entry last
        let default_entry = &self.default_entry;
        if !default_entry.is_empty() {
            return default_entry.allowance(&url_str);
        }
        // agent not found ==> access granted
        true
    }

    /// Returns the crawl delay for this user agent as a `Duration`, or None if no crawl delay is defined.
    pub fn crawl_delay<T: AsRef<str>>(&self, useragent: T) -> Option<Duration> {
        let useragent = useragent.as_ref();
        let entries = &self.entries;
        for entry in &*entries {
            if entry.applies_to(useragent) {
                return entry.crawl_delay();
            }
        }
        None
    }

    /// Returns the sitemaps for this user agent as a `Vec<Url>`.
    pub fn sitemaps<T: AsRef<str>>(&self, useragent: T) -> Option<&Vec<Url>> {
        let useragent = useragent.as_ref();
        let entries = &self.entries;
        for entry in &*entries {
            if entry.applies_to(useragent) {
                return Some(entry.sitemaps());
            }
        }
        None
    }

    /// Returns the request rate for this user agent as a `RequestRate`, or None if not request rate is defined
    pub fn request_rate<T: AsRef<str>>(&self, useragent: T) -> Option<RequestRate> {
        let useragent = useragent.as_ref();
        let entries = &self.entries;
        for entry in &*entries {
            if entry.applies_to(useragent) {
                return entry.request_rate();
            }
        }
        None
    }
}
