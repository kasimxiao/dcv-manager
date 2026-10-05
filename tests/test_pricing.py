"""机型单价：解析价格接口返回、缓存、查询不到的机型。不访问 AWS。"""
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(__file__)), "backend"))


class FakePricing:
    def __init__(self, table):
        self.table, self.calls = table, 0

    def get_products(self, ServiceCode, MaxResults, Filters):
        self.calls += 1
        f = {x["Field"]: x["Value"] for x in Filters}
        assert f["operatingSystem"] == "Windows" and f["tenancy"] == "Shared" and f["preInstalledSw"] == "NA"
        p = self.table.get((f["regionCode"], f["instanceType"]))
        if p is None:
            return {"PriceList": []}
        doc = {"terms": {"OnDemand": {"x": {"priceDimensions": {"y": {"pricePerUnit": {"USD": str(p)}}}}}}}
        return {"PriceList": [json.dumps(doc)]}


def test_prices_parse_cache_and_missing(monkeypatch, tmp_path):
    import pricing_service as ps
    fake = FakePricing({("r1", "g6f.xlarge"): 0.481, ("r1", "g4dn.xlarge"): 0.842})
    monkeypatch.setattr(ps.aws_service, "client", lambda svc, region=None: fake)
    monkeypatch.setattr(ps, "_CACHE_FILE", str(tmp_path / "c.json"))
    monkeypatch.setattr(ps, "_cache", {})
    got = ps.prices("r1", ["g6f.xlarge", "g4dn.xlarge", "g5.xlarge"])
    assert got == {"g6f.xlarge": 0.481, "g4dn.xlarge": 0.842, "g5.xlarge": None}
    n = fake.calls
    assert ps.prices("r1", ["g6f.xlarge", "g5.xlarge"]) == {"g6f.xlarge": 0.481, "g5.xlarge": None}
    assert fake.calls == n  # 命中缓存（包括无报价的机型）
    assert json.load(open(tmp_path / "c.json"))["r1"]["prices"]["g4dn.xlarge"] == 0.842


def test_failed_query_keeps_old_price(monkeypatch, tmp_path):
    import pricing_service as ps
    monkeypatch.setattr(ps, "_CACHE_FILE", str(tmp_path / "c.json"))
    monkeypatch.setattr(ps, "_cache", {"r1": {"ts": 0, "prices": {"g6f.xlarge": 0.5}}})

    class Boom:
        def get_products(self, **k):
            raise RuntimeError("throttled")
    monkeypatch.setattr(ps.aws_service, "client", lambda svc, region=None: Boom())
    assert ps.refresh("r1", ["g6f.xlarge"])["g6f.xlarge"] == 0.5
