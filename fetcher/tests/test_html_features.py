from phishguard_fetcher.html_features import StaticHtmlFeatureParser


def test_parser_returns_structural_features_only() -> None:
    parser = StaticHtmlFeatureParser("https://example.com/login")
    parser.feed(
        """
        <form action="https://collector.invalid/submit">
          <input type="password"><input type="hidden">
        </form>
        <a href="/help">Help</a><a href="https://elsewhere.invalid/">Elsewhere</a>
        <script>alert('never executed')</script>
        <meta http-equiv="refresh" content="0; url=/next">
        """
    )
    assert parser.features() == {
        "forms": 1,
        "password_inputs": 1,
        "hidden_inputs": 1,
        "external_form_actions": 1,
        "external_links": 1,
        "script_tags_present": True,
        "meta_refresh_present": True,
    }

