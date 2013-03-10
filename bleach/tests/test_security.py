"""More advanced security tests"""

from nose.tools import eq_

from bleach import clean


def test_nested_script_tag():
    eq_('&lt;&lt;script&gt;script&gt;evil()&lt;&lt;/script&gt;/script&gt;',
        clean('<<script>script>evil()<</script>/script>'))
    eq_('&lt;&lt;x&gt;script&gt;evil()&lt;&lt;/x&gt;/script&gt;',
        clean('<<x>script>evil()<</x>/script>'))

# Test with strip tags mode 1 (don't delete the content of the illegal tag)
def test_nested_script_tag_strip1():
    eq_('&lt;script&gt;evil()&lt;/script&gt;',
        clean('<<script>script>evil()<</script>/script>', strip = 1))
    eq_('&lt;script&gt;evil()&lt;/script&gt;',
        clean('<<x>script>evil()<</x>/script>', strip = 1))

# Test with strip tags mode 2 (delete the content of the illegal tag)
def test_nested_script_tag_strip2():
    eq_('&lt;/script&gt;',
        clean('<<script>script>evil()<</script>/script>', strip = 2))
    eq_('&lt;/script&gt;',
        clean('<<x>script>evil()<</x>/script>', strip = 2))

# Test case suggested here: https://github.com/jsocol/bleach/pull/57
# Without striping
def test_suggested_on_github_without_strip1():
    eq_('<p>Some random text &lt;script&gt;function with_a_(script) { alert("tag &lt;script&gt; inside a js string"); }&lt;/script&gt; without cutting away the after-script-tag text</p>',
        clean('<p>Some random text <script>function with_a_(script) { alert("tag <script> inside a js string"); }</script> without cutting away the after-script-tag text</p>', ('p')))

# Strip mode 1
def test_suggested_on_github_without_strip1():
    eq_('<p>Some random text function with_a_(script) { alert("tag  inside a js string"); } without cutting away the after-script-tag text</p>',
        clean('<p>Some random text <script>function with_a_(script) { alert("tag <script> inside a js string"); }</script> without cutting away the after-script-tag text</p>', ('p'), strip = 1))

# Strip mode 2
def test_suggested_on_github_without_strip1():
    eq_('<p>Some random text  without cutting away the after-script-tag text</p>',
        clean('<p>Some random text <script>function with_a_(script) { alert("tag <script> inside a js string"); }</script> without cutting away the after-script-tag text</p>', ('p'), strip = 2))


def test_nested_script_tag_r():
    eq_('&lt;script&lt;script&gt;&gt;evil()&lt;/script&lt;&gt;&gt;',
        clean('<script<script>>evil()</script</script>>'))


def test_invalid_attr():
    IMG = ['img', ]
    IMG_ATTR = ['src']

    eq_('<a href="test">test</a>',
        clean('<a onclick="evil" href="test">test</a>'))
    eq_('<img src="test">',
        clean('<img onclick="evil" src="test" />',
                tags=IMG, attributes=IMG_ATTR))
    eq_('<img src="test">',
        clean('<img href="invalid" src="test" />',
                tags=IMG, attributes=IMG_ATTR))


def test_unquoted_attr():
    eq_('<abbr title="mytitle">myabbr</abbr>',
        clean('<abbr title=mytitle>myabbr</abbr>'))


def test_unquoted_event_handler():
    eq_('<a href="http://xx.com">xx.com</a>',
        clean('<a href="http://xx.com" onclick=foo()>xx.com</a>'))


def test_invalid_attr_value():
    eq_('&lt;img src="javascript:alert(\'XSS\');"&gt;',
        clean('<img src="javascript:alert(\'XSS\');">'))


def test_invalid_href_attr():
    eq_('<a>xss</a>',
        clean('<a href="javascript:alert(\'XSS\')">xss</a>'))


def test_invalid_filter_attr():
    IMG = ['img', ]
    IMG_ATTR = {'img': lambda n, v: n == 'src' and v == "http://example.com/"}

    eq_('<img src="http://example.com/">',
        clean('<img onclick="evil" src="http://example.com/" />',
                tags=IMG, attributes=IMG_ATTR))

    eq_('<img>', clean('<img onclick="evil" src="http://badhost.com/" />',
                       tags=IMG, attributes=IMG_ATTR))


def test_invalid_tag_char():
    eq_('&lt;script xss="" src="http://xx.com/xss.js"&gt;&lt;/script&gt;',
        clean('<script/xss src="http://xx.com/xss.js"></script>'))
    eq_('&lt;script src="http://xx.com/xss.js"&gt;&lt;/script&gt;',
        clean('<script/src="http://xx.com/xss.js"></script>'))


def test_unclosed_tag():
    eq_('&lt;script src="http://xx.com/xss.js&amp;lt;b"&gt;',
        clean('<script src=http://xx.com/xss.js<b>'))
    eq_('&lt;script src="http://xx.com/xss.js" &lt;b=""&gt;',
        clean('<script src="http://xx.com/xss.js"<b>'))
    eq_('&lt;script src="http://xx.com/xss.js" &lt;b=""&gt;',
        clean('<script src="http://xx.com/xss.js" <b>'))


def test_strip():
    """Using strip=True shouldn't result in malicious content."""
    s = '<scri<script>pt>alert(1)</scr</script>ipt>'
    eq_('pt&gt;alert(1)ipt&gt;', clean(s, strip=True))
    s = '<scri<scri<script>pt>pt>alert(1)</script>'
    eq_('pt&gt;pt&gt;alert(1)', clean(s, strip=True))


def test_nasty():
    """Nested, broken up, multiple tags, are still foiled!"""
    test = ('<scr<script></script>ipt type="text/javascript">alert("foo");</'
            '<script></script>script<del></del>>')
    expect = (u'&lt;scr&lt;script&gt;&lt;/script&gt;ipt type="text/javascript"'
              u'&gt;alert("foo");&lt;/script&gt;script&lt;del&gt;&lt;/del&gt;'
              u'&gt;')
    eq_(expect, clean(test))


def test_poster_attribute():
    """Poster attributes should not allow javascript."""
    tags = ['video']
    attrs = {'video': ['poster']}
    test = '<video poster="javascript:alert(1)"></video>'
    expect = '<video></video>'
    eq_(expect, clean(test, tags=tags, attributes=attrs))
    ok = '<video poster="/foo.png"></video>'
    eq_(ok, clean(ok, tags=tags, attributes=attrs))


def test_feed_protocol():
    eq_('<a>foo</a>', clean('<a href="feed:file:///tmp/foo">foo</a>'))
