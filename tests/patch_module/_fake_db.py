from __future__ import annotations

from typing import Any, Dict, List


class FakeCursor:
    def __init__(self, docs: List[Dict[str, Any]]):
        self._docs = docs

    def __aiter__(self):
        self._iter = iter(self._docs)
        return self

    async def __anext__(self):
        try:
            return next(self._iter)
        except StopIteration:
            raise StopAsyncIteration


class FakeCollection:
    def __init__(self):
        self.docs: List[Dict[str, Any]] = []

    async def insert_one(self, doc: Dict[str, Any]):
        self.docs.append(doc)
        return {"inserted_id": doc.get("patch_id")}

    async def find_one(self, query: Dict[str, Any]):
        for doc in self.docs:
            if _match(doc, query):
                return doc
        return None

    async def update_one(self, query: Dict[str, Any], update: Dict[str, Any], upsert: bool = False):
        for doc in self.docs:
            if _match(doc, query):
                if "$set" in update:
                    doc.update(update["$set"])
                return type("Result", (), {"modified_count": 1})
        if upsert:
            doc = dict(query)
            if "$set" in update:
                doc.update(update["$set"])
            self.docs.append(doc)
            return type("Result", (), {"modified_count": 1})
        return type("Result", (), {"modified_count": 0})

    def find(self, query: Dict[str, Any]):
        results = [doc for doc in self.docs if _match(doc, query)]
        return FakeCursor(results)


class FakeDB:
    def __init__(self):
        self.patches = FakeCollection()
        self.patch_apply_requests = FakeCollection()
        self.patch_rate_limits = FakeCollection()
        self.scans = FakeCollection()


def _match(doc: Dict[str, Any], query: Dict[str, Any]) -> bool:
    for key, value in query.items():
        if isinstance(value, dict) and "$in" in value:
            if doc.get(key) not in value["$in"]:
                return False
        else:
            if doc.get(key) != value:
                return False
    return True
