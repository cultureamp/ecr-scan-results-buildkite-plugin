def cap($s):
    $s[0:1] + ($s[1:]|ascii_downcase);

def td($c):
    "<td>\(if ($c|length)>0 then ($c | @html) else "&nbsp;" end)</td>";

def tda($ref; $txt):
    if ($ref | length) > 0 then
        "<td><a href=\"\($ref)\">\($txt|@html)</a></td>"
    else
        td($txt)
    end;

def attr(x; $n):
    (
        x
        | .attributes[]
        | select(.key == $n)
        | .value
    ) // "";

def attrh(x; $n):
    attr(x;$n)
    | @html;

def scorelink($vector):
    if ($vector | length) > 0 then
        @uri "https://nvd.nist.gov/vuln-metrics/cvss/v2-calculator?vector=(\($vector))"
    else
        ""
    end;

.imageScanFindings
| "<table>",
(
    .findings[]
    | (
        "<tr>",
        tda(.uri; .name),
        td(cap(.severity)),
        td(attrh(.;"package_name") + " " + attrh(.;"package_version")),
        td(attrh(.;"CVSS2_SCORE")),
        tda(scorelink(attr(.;"CVSS2_VECTOR"));attrh(.;"CVSS2_VECTOR")),
        "</tr>"
    )
),
"</table>",
"<p><i>scanned: \(.imageScanCompletedAt | @html)</i></p>"
