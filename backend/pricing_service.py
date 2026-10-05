"""机型单价：从 AWS Price List API 查询按需价格（Windows、共享租户、无预装软件），按区域缓存 24 小时。

价格接口只在 us-east-1 等少数区域提供，但可以查询所有区域的价格。
单价不含 EBS 磁盘、公网 IPv4、数据传输等费用。
"""
import json
import logging
import os
import threading
import time
import concurrent.futures as cf

import aws_service
import config

log = logging.getLogger("dcv.pricing")
TTL = 24 * 3600
_CACHE_FILE = os.path.join(os.path.dirname(config.DB_PATH), ".price-cache.json")
_lock = threading.Lock()
_cache = {}          # {region: {"ts": float, "prices": {type: float}}}
_loading = set()


def _load_disk():
    try:
        with open(_CACHE_FILE, encoding="utf-8") as f:
            _cache.update(json.load(f))
    except (OSError, ValueError):
        pass


def _save_disk():
    try:
        tmp = _CACHE_FILE + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(_cache, f)
        os.replace(tmp, _CACHE_FILE)
    except OSError:
        log.warning("保存价格缓存失败", exc_info=True)


_load_disk()


def _query(region, itype):
    pr = aws_service.client("pricing", "us-east-1")
    flt = {"instanceType": itype, "regionCode": region, "operatingSystem": "Windows", "tenancy": "Shared",
           "preInstalledSw": "NA", "capacitystatus": "Used", "licenseModel": "No License required"}
    r = pr.get_products(ServiceCode="AmazonEC2", MaxResults=10,
                        Filters=[{"Type": "TERM_MATCH", "Field": k, "Value": v} for k, v in flt.items()])
    for raw in r.get("PriceList", []):
        d = json.loads(raw)
        for term in d.get("terms", {}).get("OnDemand", {}).values():
            for dim in term.get("priceDimensions", {}).values():
                usd = float(dim.get("pricePerUnit", {}).get("USD", "0") or 0)
                if usd > 0:
                    return usd
    return None


def refresh(region, types=None):
    types = list(dict.fromkeys(types or config.ALLOWED_INSTANCE_TYPES))
    with cf.ThreadPoolExecutor(max_workers=6) as ex:
        got = dict(zip(types, ex.map(lambda t: _safe_query(region, t), types)))
    with _lock:
        old = (_cache.get(region) or {}).get("prices", {})
        # 查询不到价格（例如该区域不提供此机型）记为 None，避免每次都重新查询；已有价格不被覆盖
        prices = {**old, **{t: p for t, p in got.items() if p is not None or t not in old}}
        _cache[region] = {"ts": time.time(), "prices": prices}
        _save_disk()
    return prices


def _safe_query(region, itype):
    try:
        return _query(region, itype)
    except Exception as e:  # noqa: BLE001
        log.warning("查询价格失败 %s %s：%s", region, itype, e)
        return None


def prices(region, types=None, wait=True):
    """{机型: 美元/小时}。缓存过期时：wait=True 同步刷新；否则后台刷新并先返回旧值。"""
    types = list(dict.fromkeys(types or config.ALLOWED_INSTANCE_TYPES))
    c = _cache.get(region)
    fresh = c and time.time() - c["ts"] < TTL and all(t in c["prices"] for t in types)
    if fresh:
        return {t: c["prices"].get(t) for t in types}
    if wait or not c:
        return {t: v for t, v in refresh(region, types).items() if t in types}
    if region not in _loading:
        _loading.add(region)

        def bg():
            try:
                refresh(region, types)
            finally:
                _loading.discard(region)
        threading.Thread(target=bg, daemon=True).start()
    return {t: c["prices"].get(t) for t in types}


def all_regions(wait=True, regions=None):
    regs = regions or config.REGIONS
    types = list(dict.fromkeys(config.ALLOWED_INSTANCE_TYPES + config.CANDIDATE_TYPES))
    with cf.ThreadPoolExecutor(max_workers=max(1, len(regs))) as ex:
        out = dict(zip(regs, ex.map(lambda r: prices(r, types, wait=wait), regs)))
    ts = min(((_cache.get(r) or {}).get("ts") or 0) for r in regs) if regs else 0
    return {"currency": "USD", "unit": "小时", "os": "Windows", "basis": "按需价格，不含磁盘、公网 IP 与流量",
            "prices": out, "fetched_at": ts}


def warm():
    """平台启动时后台预热价格缓存。"""
    threading.Thread(target=lambda: all_regions(wait=True), daemon=True).start()
