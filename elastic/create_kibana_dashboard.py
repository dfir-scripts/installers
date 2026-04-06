#!/usr/bin/env python3
"""
Creates a Kibana data view and a Lens-based TLN dashboard via the Kibana API.
Tested against Kibana 8.17.
"""
import json, requests, sys

KB = "http://localhost:5601"
HEADERS = {"kbn-xsrf": "true", "Content-Type": "application/json"}

def post(path, body, refs=None):
    payload = body.copy()
    if refs is not None:
        payload["references"] = refs
    r = requests.post(f"{KB}{path}", headers=HEADERS, json=payload, timeout=30)
    if r.status_code not in (200, 201, 409):
        print(f"  ERROR {r.status_code} on {path}: {r.text[:300]}")
        return None
    return r.json()

def put(path, body):
    r = requests.put(f"{KB}{path}", headers=HEADERS, json=body, timeout=30)
    if r.status_code not in (200, 201):
        print(f"  ERROR {r.status_code} on {path}: {r.text[:300]}")
        return None
    return r.json()

def delete(path):
    r = requests.delete(f"{KB}{path}", headers=HEADERS, timeout=10)
    return r.status_code

# ── 1. Create data view ────────────────────────────────────────────────────────
print("Creating data view...")
delete("/api/data_views/data_view/tln-dataview")
res = post("/api/data_views/data_view", {
    "data_view": {
        "id": "tln-dataview",
        "title": "tln-*",
        "timeFieldName": "@timestamp",
        "name": "TLN Timeline"
    }
})
if res:
    print(f"  Data view created: {res.get('data_view',{}).get('id','?')}")

# ── 2. Events over time (date histogram) ──────────────────────────────────────
print("Creating 'Events Over Time' visualization...")
res = post("/api/saved_objects/lens", {
    "attributes": {
        "title": "TLN - Events Over Time",
        "visualizationType": "lnsXY",
        "state": {
            "datasourceStates": {
                "formBased": {
                    "layers": {
                        "layer1": {
                            "columnOrder": ["col_date", "col_count"],
                            "columns": {
                                "col_date": {
                                    "dataType": "date",
                                    "isBucketed": True,
                                    "label": "@timestamp",
                                    "operationType": "date_histogram",
                                    "params": {"interval": "auto"},
                                    "scale": "interval",
                                    "sourceField": "@timestamp"
                                },
                                "col_count": {
                                    "dataType": "number",
                                    "isBucketed": False,
                                    "label": "Event Count",
                                    "operationType": "count",
                                    "scale": "ratio",
                                    "sourceField": "___records___"
                                }
                            },
                            "indexPatternId": "tln-dataview"
                        }
                    }
                }
            },
            "filters": [],
            "query": {"language": "kuery", "query": ""},
            "visualization": {
                "axisTitlesVisibilitySettings": {"x": True, "yLeft": True, "yRight": True},
                "curveType": "LINEAR",
                "fittingFunction": "None",
                "gridlinesVisibilitySettings": {"x": False, "yLeft": True, "yRight": True},
                "layers": [{
                    "accessors": ["col_count"],
                    "layerId": "layer1",
                    "layerType": "data",
                    "seriesType": "bar_stacked",
                    "xAccessor": "col_date",
                    "yConfig": [{"forAccessor": "col_count", "color": "#1BA9F5"}]
                }],
                "legend": {"isVisible": True, "position": "right"},
                "preferredSeriesType": "bar_stacked",
                "tickLabelsVisibilitySettings": {"x": True, "yLeft": True, "yRight": True},
                "valueLabels": "hide"
            }
        },
    }
},
refs=[{"id": "tln-dataview", "name": "indexpattern-datasource-layer-layer1", "type": "index-pattern"}]
)
vis1_id = res.get("id") if res else None
print(f"  ID: {vis1_id}")

# ── 3. Event source breakdown (pie) ───────────────────────────────────────────
print("Creating 'Event Source Breakdown' visualization...")
res = post("/api/saved_objects/lens", {
    "attributes": {
        "title": "TLN - Event Source Breakdown",
        "visualizationType": "lnsPie",
        "state": {
            "datasourceStates": {
                "formBased": {
                    "layers": {
                        "layer1": {
                            "columnOrder": ["col_src", "col_count"],
                            "columns": {
                                "col_src": {
                                    "dataType": "string",
                                    "isBucketed": True,
                                    "label": "Event Source",
                                    "operationType": "terms",
                                    "params": {
                                        "field": "tln_source.keyword",
                                        "orderBy": {"columnId": "col_count", "type": "column"},
                                        "orderDirection": "desc",
                                        "size": 20,
                                        "otherBucket": True,
                                        "missingBucket": False
                                    },
                                    "scale": "ordinal",
                                    "sourceField": "tln_source.keyword"
                                },
                                "col_count": {
                                    "dataType": "number",
                                    "isBucketed": False,
                                    "label": "Count",
                                    "operationType": "count",
                                    "scale": "ratio",
                                    "sourceField": "___records___"
                                }
                            },
                            "indexPatternId": "tln-dataview"
                        }
                    }
                }
            },
            "filters": [],
            "query": {"language": "kuery", "query": ""},
            "visualization": {
                "layers": [{
                    "categoryDisplay": "default",
                    "layerId": "layer1",
                    "layerType": "data",
                    "legendDisplay": "default",
                    "metrics": ["col_count"],
                    "nestedLegend": False,
                    "numberDisplay": "percent",
                    "primaryGroups": ["col_src"]
                }],
                "shape": "pie"
            }
        },
    }
},
refs=[{"id": "tln-dataview", "name": "indexpattern-datasource-layer-layer1", "type": "index-pattern"}]
)
vis2_id = res.get("id") if res else None
print(f"  ID: {vis2_id}")

# ── 4. Top Hosts bar chart ─────────────────────────────────────────────────────
print("Creating 'Top Hosts' visualization...")
res = post("/api/saved_objects/lens", {
    "attributes": {
        "title": "TLN - Top Hosts",
        "visualizationType": "lnsXY",
        "state": {
            "datasourceStates": {
                "formBased": {
                    "layers": {
                        "layer1": {
                            "columnOrder": ["col_host", "col_count"],
                            "columns": {
                                "col_host": {
                                    "dataType": "string",
                                    "isBucketed": True,
                                    "label": "Hostname",
                                    "operationType": "terms",
                                    "params": {
                                        "field": "hostname.keyword",
                                        "orderBy": {"columnId": "col_count", "type": "column"},
                                        "orderDirection": "desc",
                                        "size": 10,
                                        "otherBucket": False,
                                        "missingBucket": False
                                    },
                                    "scale": "ordinal",
                                    "sourceField": "hostname.keyword"
                                },
                                "col_count": {
                                    "dataType": "number",
                                    "isBucketed": False,
                                    "label": "Event Count",
                                    "operationType": "count",
                                    "scale": "ratio",
                                    "sourceField": "___records___"
                                }
                            },
                            "indexPatternId": "tln-dataview"
                        }
                    }
                }
            },
            "filters": [],
            "query": {"language": "kuery", "query": ""},
            "visualization": {
                "axisTitlesVisibilitySettings": {"x": True, "yLeft": True, "yRight": True},
                "fittingFunction": "None",
                "gridlinesVisibilitySettings": {"x": False, "yLeft": True, "yRight": True},
                "layers": [{
                    "accessors": ["col_count"],
                    "layerId": "layer1",
                    "layerType": "data",
                    "seriesType": "bar_horizontal",
                    "xAccessor": "col_host",
                    "yConfig": [{"forAccessor": "col_count", "color": "#6092C0"}]
                }],
                "legend": {"isVisible": False, "position": "right"},
                "preferredSeriesType": "bar_horizontal",
                "tickLabelsVisibilitySettings": {"x": True, "yLeft": True, "yRight": True},
                "valueLabels": "hide"
            }
        },
    }
},
refs=[{"id": "tln-dataview", "name": "indexpattern-datasource-layer-layer1", "type": "index-pattern"}]
)
vis3_id = res.get("id") if res else None
print(f"  ID: {vis3_id}")

# ── 5. Top Users bar chart ─────────────────────────────────────────────────────
print("Creating 'Top Users' visualization...")
res = post("/api/saved_objects/lens", {
    "attributes": {
        "title": "TLN - Top Users",
        "visualizationType": "lnsXY",
        "state": {
            "datasourceStates": {
                "formBased": {
                    "layers": {
                        "layer1": {
                            "columnOrder": ["col_user", "col_count"],
                            "columns": {
                                "col_user": {
                                    "dataType": "string",
                                    "isBucketed": True,
                                    "label": "Username",
                                    "operationType": "terms",
                                    "params": {
                                        "field": "username.keyword",
                                        "orderBy": {"columnId": "col_count", "type": "column"},
                                        "orderDirection": "desc",
                                        "size": 10,
                                        "otherBucket": False,
                                        "missingBucket": False
                                    },
                                    "scale": "ordinal",
                                    "sourceField": "username.keyword"
                                },
                                "col_count": {
                                    "dataType": "number",
                                    "isBucketed": False,
                                    "label": "Event Count",
                                    "operationType": "count",
                                    "scale": "ratio",
                                    "sourceField": "___records___"
                                }
                            },
                            "indexPatternId": "tln-dataview"
                        }
                    }
                }
            },
            "filters": [],
            "query": {"language": "kuery", "query": ""},
            "visualization": {
                "axisTitlesVisibilitySettings": {"x": True, "yLeft": True, "yRight": True},
                "fittingFunction": "None",
                "gridlinesVisibilitySettings": {"x": False, "yLeft": True, "yRight": True},
                "layers": [{
                    "accessors": ["col_count"],
                    "layerId": "layer1",
                    "layerType": "data",
                    "seriesType": "bar_horizontal",
                    "xAccessor": "col_user",
                    "yConfig": [{"forAccessor": "col_count", "color": "#D36086"}]
                }],
                "legend": {"isVisible": False, "position": "right"},
                "preferredSeriesType": "bar_horizontal",
                "tickLabelsVisibilitySettings": {"x": True, "yLeft": True, "yRight": True},
                "valueLabels": "hide"
            }
        },
    }
},
refs=[{"id": "tln-dataview", "name": "indexpattern-datasource-layer-layer1", "type": "index-pattern"}]
)
vis4_id = res.get("id") if res else None
print(f"  ID: {vis4_id}")

# ── 6. Events table (datatable) ───────────────────────────────────────────────
print("Creating 'Events Table' visualization...")
res = post("/api/saved_objects/lens", {
    "attributes": {
        "title": "TLN - Events Table",
        "visualizationType": "lnsDatatable",
        "state": {
            "datasourceStates": {
                "formBased": {
                    "layers": {
                        "layer1": {
                            "columnOrder": ["col_ts", "col_src", "col_host", "col_user", "col_desc"],
                            "columns": {
                                "col_ts": {
                                    "dataType": "date",
                                    "isBucketed": True,
                                    "label": "Timestamp",
                                    "operationType": "date_histogram",
                                    "params": {"interval": "1h"},
                                    "scale": "interval",
                                    "sourceField": "@timestamp"
                                },
                                "col_src": {
                                    "dataType": "string",
                                    "isBucketed": True,
                                    "label": "Source",
                                    "operationType": "terms",
                                    "params": {
                                        "field": "tln_source.keyword",
                                        "orderBy": {"type": "alphabetical"},
                                        "orderDirection": "asc",
                                        "size": 100,
                                        "otherBucket": False,
                                        "missingBucket": False
                                    },
                                    "scale": "ordinal",
                                    "sourceField": "tln_source.keyword"
                                },
                                "col_host": {
                                    "dataType": "string",
                                    "isBucketed": True,
                                    "label": "Host",
                                    "operationType": "terms",
                                    "params": {
                                        "field": "hostname.keyword",
                                        "orderBy": {"type": "alphabetical"},
                                        "orderDirection": "asc",
                                        "size": 100,
                                        "otherBucket": False,
                                        "missingBucket": False
                                    },
                                    "scale": "ordinal",
                                    "sourceField": "hostname.keyword"
                                },
                                "col_user": {
                                    "dataType": "string",
                                    "isBucketed": True,
                                    "label": "User",
                                    "operationType": "terms",
                                    "params": {
                                        "field": "username.keyword",
                                        "orderBy": {"type": "alphabetical"},
                                        "orderDirection": "asc",
                                        "size": 100,
                                        "otherBucket": False,
                                        "missingBucket": False
                                    },
                                    "scale": "ordinal",
                                    "sourceField": "username.keyword"
                                },
                                "col_desc": {
                                    "dataType": "number",
                                    "isBucketed": False,
                                    "label": "Count",
                                    "operationType": "count",
                                    "scale": "ratio",
                                    "sourceField": "___records___"
                                }
                            },
                            "indexPatternId": "tln-dataview"
                        }
                    }
                }
            },
            "filters": [],
            "query": {"language": "kuery", "query": ""},
            "visualization": {
                "columns": [
                    {"columnId": "col_ts"},
                    {"columnId": "col_src"},
                    {"columnId": "col_host"},
                    {"columnId": "col_user"},
                    {"columnId": "col_desc"}
                ],
                "layerId": "layer1",
                "layerType": "data",
                "rowHeight": "single",
                "rowHeightLines": 1,
                "sorting": {"columnId": "col_ts", "direction": "asc"}
            }
        },
    }
},
refs=[{"id": "tln-dataview", "name": "indexpattern-datasource-layer-layer1", "type": "index-pattern"}]
)
vis5_id = res.get("id") if res else None
print(f"  ID: {vis5_id}")

# ── 7. Create dashboard ────────────────────────────────────────────────────────
print("Creating dashboard...")
delete("/api/saved_objects/dashboard/tln-dashboard")

panels = []
if vis1_id:
    panels.append({
        "version": "8.17.0",
        "type": "lens",
        "gridData": {"x": 0, "y": 0, "w": 48, "h": 15, "i": "p1"},
        "panelIndex": "p1",
        "embeddableConfig": {"enhancements": {}},
        "panelRefName": "panel_p1"
    })
if vis2_id:
    panels.append({
        "version": "8.17.0",
        "type": "lens",
        "gridData": {"x": 0, "y": 15, "w": 24, "h": 15, "i": "p2"},
        "panelIndex": "p2",
        "embeddableConfig": {"enhancements": {}},
        "panelRefName": "panel_p2"
    })
if vis3_id:
    panels.append({
        "version": "8.17.0",
        "type": "lens",
        "gridData": {"x": 24, "y": 15, "w": 24, "h": 15, "i": "p3"},
        "panelIndex": "p3",
        "embeddableConfig": {"enhancements": {}},
        "panelRefName": "panel_p3"
    })
if vis4_id:
    panels.append({
        "version": "8.17.0",
        "type": "lens",
        "gridData": {"x": 0, "y": 30, "w": 24, "h": 15, "i": "p4"},
        "panelIndex": "p4",
        "embeddableConfig": {"enhancements": {}},
        "panelRefName": "panel_p4"
    })
if vis5_id:
    panels.append({
        "version": "8.17.0",
        "type": "lens",
        "gridData": {"x": 24, "y": 30, "w": 24, "h": 15, "i": "p5"},
        "panelIndex": "p5",
        "embeddableConfig": {"enhancements": {}},
        "panelRefName": "panel_p5"
    })

references = [{"id": "tln-dataview", "name": "tln-dataview", "type": "index-pattern"}]
if vis1_id: references.append({"id": vis1_id, "name": "panel_p1", "type": "lens"})
if vis2_id: references.append({"id": vis2_id, "name": "panel_p2", "type": "lens"})
if vis3_id: references.append({"id": vis3_id, "name": "panel_p3", "type": "lens"})
if vis4_id: references.append({"id": vis4_id, "name": "panel_p4", "type": "lens"})
if vis5_id: references.append({"id": vis5_id, "name": "panel_p5", "type": "lens"})

res = post("/api/saved_objects/dashboard/tln-dashboard", {
    "attributes": {
        "title": "TLN Timeline Analysis",
        "description": "Forensic timeline analysis dashboard for TLN files",
        "panelsJSON": json.dumps(panels),
        "optionsJSON": json.dumps({"useMargins": True, "syncColors": False, "hidePanelTitles": False}),
        "timeFrom": "2005-08-09T00:00:00.000Z",
        "timeTo": "2005-08-11T23:59:59.000Z",
        "timeRestore": False,
        "kibanaSavedObjectMeta": {
            "searchSourceJSON": json.dumps({"query": {"language": "kuery", "query": ""}, "filter": []})
        }
    },
    "references": references
})
if res:
    print(f"  Dashboard created: {res.get('id','?')}")
    print(f"\nDone! Open: http://localhost:5601/app/dashboards#/view/tln-dashboard")
    print(f"Set time range to: 2005-08-09 to 2005-08-11")
else:
    print("  Dashboard creation failed")
