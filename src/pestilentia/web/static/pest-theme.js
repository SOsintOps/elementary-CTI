// Elementary CTI shared front-end theme (see UI-SPEC.md)
// Single source of truth for chart theming and the ISO country mapping —
// templates must not redefine these.
window.PEST = {
    isDark: function () { return document.documentElement.classList.contains('dark'); },
    font: function () {
        return { family: "'Inter', system-ui, sans-serif", size: 11, color: this.isDark() ? '#d4d4d4' : '#475569' };
    },
    status: { ok: '#68b723', warn: '#f9c440', down: '#ed5353', off: '#95a3ab' },  // Lime/Banana/Strawberry/Slate (elementary OS)
    // Sequential scale for victim-count choropleths (YlOrRd)
    choroScale: [[0, '#ffffb2'], [0.25, '#fecc5c'], [0.5, '#fd8d3c'], [0.75, '#f03b20'], [1, '#bd0026']],
    // topojsonURL: Plotly fetches world boundaries at *render* time; the
    // default is cdn.plot.ly, which the CSP (connect-src 'self') blocks and
    // the no-remote-assets rule forbids anyway. Trailing slash required.
    // Any future geo scope/resolution beyond the defaults must vendor its
    // file here too, or the map goes blank with only a console CSP error.
    plotlyConfig: { responsive: true, displayModeBar: false, topojsonURL: '/static/vendor/plotly-topojson/' },
    _geoBase: function () {
        var dark = this.isDark();
        return {
            bgcolor: 'rgba(0,0,0,0)',
            showframe: false,
            showland: true,
            landcolor: dark ? '#273445' : '#e0e0e0',
            showocean: true,
            oceancolor: dark ? '#16263d' : '#dbeafe',
            showcoastlines: true,
            coastlinecolor: dark ? '#3a4a5e' : '#d1d5db',
            showcountries: true,
            countrycolor: dark ? '#3a4a5e' : '#d1d5db',
            projection: { type: 'natural earth' }
        };
    },
    // Accent hue for single-series time charts (Blueberry 500 / 300 on dark).
    accent: function () { return this.isDark() ? '#64baff' : '#3689e6'; },
    // Translucent fill under the line — same hue, never a second colour.
    accentFill: function () { return this.isDark() ? 'rgba(100,186,255,0.16)' : 'rgba(54,137,230,0.14)'; },
    // Shared layout for single-series time charts: recessive grid, no legend
    // (one series — the card title names it), crosshair + unified tooltip.
    timeSeriesLayout: function (extra) {
        extra = extra || {};
        var dark = this.isDark();
        var grid = dark ? '#273445' : '#eef0f2';
        var axis = dark ? '#3a4a5e' : '#e5e7eb';
        return Object.assign({
            paper_bgcolor: 'rgba(0,0,0,0)',
            plot_bgcolor: 'rgba(0,0,0,0)',
            font: this.font(),
            margin: { t: 8, b: 28, l: 40, r: 12 },
            showlegend: false,
            hovermode: 'x unified',
            hoverlabel: {
                bgcolor: dark ? '#1a2433' : '#ffffff',
                bordercolor: axis,
                font: this.font()
            },
            xaxis: {
                showgrid: false,
                zeroline: false,
                linecolor: axis,
                ticks: 'outside',
                tickcolor: axis,
                showspikes: true,
                spikemode: 'across',
                spikethickness: 1,
                spikedash: 'dot',
                spikecolor: dark ? '#3a4a5e' : '#cbd5e1'
            },
            yaxis: {
                showgrid: true,
                gridcolor: grid,
                zeroline: false,
                linecolor: 'rgba(0,0,0,0)',
                rangemode: 'tozero',
                ticks: ''
            }
        }, extra);
    },
    geoLayout: function (extra) {
        extra = extra || {};
        var layout = Object.assign({
            paper_bgcolor: 'rgba(0,0,0,0)',
            plot_bgcolor: 'rgba(0,0,0,0)',
            font: this.font(),
            margin: { t: 0, b: 0, l: 0, r: 0 }
        }, extra);
        layout.geo = Object.assign({}, this._geoBase(), extra.geo || {});
        return layout;
    },
    iso2to3: {"AF":"AFG","AL":"ALB","DZ":"DZA","AD":"AND","AO":"AGO","AG":"ATG","AR":"ARG","AM":"ARM","AU":"AUS","AT":"AUT","AZ":"AZE","BS":"BHS","BH":"BHR","BD":"BGD","BB":"BRB","BY":"BLR","BE":"BEL","BZ":"BLZ","BJ":"BEN","BT":"BTN","BO":"BOL","BA":"BIH","BW":"BWA","BR":"BRA","BN":"BRN","BG":"BGR","BF":"BFA","BI":"BDI","KH":"KHM","CM":"CMR","CA":"CAN","CF":"CAF","TD":"TCD","CL":"CHL","CN":"CHN","CO":"COL","KM":"COM","CG":"COG","CD":"COD","CR":"CRI","CI":"CIV","HR":"HRV","CU":"CUB","CY":"CYP","CZ":"CZE","DK":"DNK","DJ":"DJI","DM":"DMA","DO":"DOM","EC":"ECU","EG":"EGY","SV":"SLV","GQ":"GNQ","ER":"ERI","EE":"EST","ET":"ETH","FJ":"FJI","FI":"FIN","FR":"FRA","GA":"GAB","GM":"GMB","GE":"GEO","DE":"DEU","GH":"GHA","GR":"GRC","GD":"GRD","GT":"GTM","GN":"GIN","GW":"GNB","GY":"GUY","HT":"HTI","HN":"HND","HU":"HUN","IS":"ISL","IN":"IND","ID":"IDN","IR":"IRN","IQ":"IRQ","IE":"IRL","IL":"ISR","IT":"ITA","JM":"JAM","JP":"JPN","JO":"JOR","KZ":"KAZ","KE":"KEN","KI":"KIR","KP":"PRK","KR":"KOR","KW":"KWT","KG":"KGZ","LA":"LAO","LV":"LVA","LB":"LBN","LS":"LSO","LR":"LBR","LY":"LBY","LI":"LIE","LT":"LTU","LU":"LUX","MK":"MKD","MG":"MDG","MW":"MWI","MY":"MYS","MV":"MDV","ML":"MLI","MT":"MLT","MH":"MHL","MR":"MRT","MU":"MUS","MX":"MEX","FM":"FSM","MD":"MDA","MC":"MCO","MN":"MNG","ME":"MNE","MA":"MAR","MZ":"MOZ","MM":"MMR","NA":"NAM","NR":"NRU","NP":"NPL","NL":"NLD","NZ":"NZL","NI":"NIC","NE":"NER","NG":"NGA","NO":"NOR","OM":"OMN","PK":"PAK","PW":"PLW","PA":"PAN","PG":"PNG","PY":"PRY","PE":"PER","PH":"PHL","PL":"POL","PT":"PRT","QA":"QAT","RO":"ROU","RU":"RUS","RW":"RWA","KN":"KNA","LC":"LCA","VC":"VCT","WS":"WSM","SM":"SMR","ST":"STP","SA":"SAU","SN":"SEN","RS":"SRB","SC":"SYC","SL":"SLE","SG":"SGP","SK":"SVK","SI":"SVN","SB":"SLB","SO":"SOM","ZA":"ZAF","ES":"ESP","LK":"LKA","SD":"SDN","SR":"SUR","SZ":"SWZ","SE":"SWE","CH":"CHE","SY":"SYR","TW":"TWN","TJ":"TJK","TZ":"TZA","TH":"THA","TL":"TLS","TG":"TGO","TO":"TON","TT":"TTO","TN":"TUN","TR":"TUR","TM":"TKM","TV":"TUV","UG":"UGA","UA":"UKR","AE":"ARE","GB":"GBR","US":"USA","UY":"URY","UZ":"UZB","VU":"VUT","VE":"VEN","VN":"VNM","YE":"YEM","ZM":"ZMB","ZW":"ZWE","HK":"HKG","XK":"XKV"}
};
