from maverick.model_guidance import clean_capabilities, parse_capabilities


def test_unknown_capability_is_not_inferred_from_missing_parameters():
    parsed = parse_capabilities('openai', {'data': [{'id': 'example', 'supported_parameters': ['temperature']}]})
    assert 'tools' not in parsed['example']
    assert 'vision' not in parsed['example']


def test_known_and_bounded_capabilities_are_kept_without_provider_secrets():
    parsed = parse_capabilities('openai', {'data': [{'id': 'example', 'supported_parameters': ['tools'],
        'context_length': 12345, 'api_key': 'synthetic-secret', 'architecture': {'input_modalities': ['image']}}]})
    assert parsed == {'example': {'tools': True, 'vision': True, 'context_tokens': 12345}}
    assert clean_capabilities({'context_tokens': True, 'output_tokens': -1, 'vision': 'yes'}) == {}
