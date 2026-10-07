from pathlib import Path


def test_app_source_has_no_mojibake_sequences():
    text = Path(__file__).resolve().parents[1].joinpath('app.py').read_text(encoding='utf-8')
    mojibake_tokens = [
        'â†’', 'â†—', 'â†', 'â†º', 'â—', 'â—', 'â—Ž', 'â—ˆ',
        'â–¦', 'âŒ•', 'â–°', 'âŒ‚', 'âœ¦', 'âœ‰', 'â‰¡', 'â‰‹',
        'âš™', 'â˜°', 'â˜·', 'â†‘', 'â‚¹', 'â€”', 'â€¦', 'â€™',
        'â€œ', 'â€', 'â€¢', 'Â·', 'Â', 'Ã'
    ]
    bad = [token for token in mojibake_tokens if token in text]
    assert not bad, f'Mojibake tokens found in app.py: {bad[:20]}'
