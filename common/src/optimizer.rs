use regex::{Match, Regex};

pub fn optimizer_v1(x: &str) -> Option<&str> {
    let re = Regex::new(
        r#"[\w.\s]+\[HKEY_LOCAL_MACHINE\\SOFTWARE\\WOW6432Node\\Wizet\\MapleStory\][^\[]+"#,
    )
    .unwrap();

    re.find(x).as_ref().map(Match::as_str)
}
