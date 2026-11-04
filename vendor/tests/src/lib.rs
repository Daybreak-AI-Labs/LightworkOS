#[cfg(test)]
mod tests {
    use glib::prelude::*;
    use urlpattern::{UrlPattern, UrlPatternInit, UrlPatternMatchInput};

    #[derive(Debug, Copy, Clone, PartialEq, Eq, glib::Enum)]
    #[enum_type(name = "LightworkDependencyRegressionState")]
    enum State {
        Ready = 0,
        Complete = 1,
    }

    #[test]
    fn macro_error_replacement_preserves_enum_expansion() {
        let value = State::Complete.to_value();
        assert_eq!(value.get::<State>().unwrap(), State::Complete);
    }

    #[test]
    fn variant_string_iterator_out_pointer_survives_optimization() {
        let value = ["first", "βeta", "third", "四", "last"].to_variant();
        assert_eq!(value.array_iter_str().unwrap().collect::<Vec<_>>(),
                   ["first", "βeta", "third", "四", "last"]);
        let mut iter = value.array_iter_str().unwrap();
        assert_eq!(iter.next(), Some("first"));
        assert_eq!(iter.nth(1), Some("third"));
        assert_eq!(iter.next_back(), Some("last"));
        assert_eq!(iter.nth_back(0), Some("四"));
        assert_eq!(iter.next(), None);
        assert_eq!(iter.next_back(), None);
        assert_eq!(value.array_iter_str().unwrap().last(), Some("last"));
        let empty = Vec::<String>::new().to_variant();
        assert_eq!(empty.array_iter_str().unwrap().next(), None);
    }

    #[test]
    fn maintained_unicode_tables_preserve_named_url_parameters() {
        for name in ["name", "Δοκιμή", "名前", "a\u{200c}b", "$id", "_id"] {
            let pattern: UrlPattern = UrlPattern::parse(UrlPatternInit {
                pathname: Some(format!("/:{name}")),
                ..Default::default()
            }, Default::default()).unwrap();
            let input = UrlPatternMatchInput::Init(UrlPatternInit {
                pathname: Some("/value".into()),
                ..Default::default()
            });
            let result = pattern.exec(input).unwrap().unwrap();
            assert_eq!(result.pathname.groups.get(name).unwrap().as_deref(), Some("value"));
        }
        assert!(<UrlPattern>::parse(UrlPatternInit {
            pathname: Some("/:1invalid".into()),
            ..Default::default()
        }, Default::default()).is_err());
    }
}
