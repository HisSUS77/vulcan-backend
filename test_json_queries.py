"""
Test script to verify JSON queries are loaded correctly
"""
from semantic_engine.query_store.loader import get_query_store

# Initialize query store
store = get_query_store()

# Get statistics
stats = store.get_stats()

print("="*60)
print("📊 QUERY STORE STATISTICS")
print("="*60)
print(f"Total Rules: {stats['total_rules']}")
print(f"\nBy Severity:")
for severity, count in sorted(stats['by_severity'].items()):
    print(f"  {severity}: {count}")
print(f"\nBy OWASP Category:")
for owasp, count in sorted(stats['by_owasp'].items()):
    print(f"  {owasp}: {count}")

print("\n" + "="*60)
print("🔍 SAMPLE RULES")
print("="*60)

# Test SQL Injection rule
sql_rule = store.get_query("SQL_INJECTION")
if sql_rule:
    print(f"\n✅ SQL_INJECTION Rule:")
    print(f"   Name: {sql_rule.name}")
    print(f"   Severity: {sql_rule.severity}")
    print(f"   CWE: {sql_rule.cwe}")
    print(f"   Sources: {len(sql_rule.sources)} patterns")
    print(f"   Sinks: {len(sql_rule.sinks)} patterns")
    print(f"   Includes PARAMETER: {'PARAMETER' in sql_rule.sources}")
    print(f"   Includes username: {'username' in sql_rule.sources}")
else:
    print("❌ SQL_INJECTION rule not found!")

# Test Command Injection rule
cmd_rule = store.get_query("COMMAND_INJECTION")
if cmd_rule:
    print(f"\n✅ COMMAND_INJECTION Rule:")
    print(f"   Name: {cmd_rule.name}")
    print(f"   Severity: {cmd_rule.severity}")
    print(f"   Sources: {len(cmd_rule.sources)}")
    print(f"   Sinks: {len(cmd_rule.sinks)}")
else:
    print("❌ COMMAND_INJECTION rule not found!")

# Test XSS rule
xss_rule = store.get_query("XSS")
if xss_rule:
    print(f"\n✅ XSS Rule:")
    print(f"   Name: {xss_rule.name}")
    print(f"   Severity: {xss_rule.severity}")
    print(f"   Sources: {len(xss_rule.sources)}")
    print(f"   Sinks: {len(xss_rule.sinks)}")

# Test new rules
print("\n" + "="*60)
print("🆕 NEW OWASP TOP 10 RULES")
print("="*60)

new_rules = [
    "TEMPLATE_INJECTION",
    "NOSQL_INJECTION",
    "JWT_WEAK_SECRET",
    "PROTOTYPE_POLLUTION",
    "GRAPHQL_INJECTION",
    "ZIPSLIP_VULNERABILITY"
]

for rule_id in new_rules:
    rule = store.get_query(rule_id)
    if rule:
        print(f"✅ {rule_id}: {rule.name} ({rule.severity})")
    else:
        print(f"❌ {rule_id}: Not found")

print("\n" + "="*60)
print("📋 ALL RULE IDs:")
print("="*60)
all_rules = store.get_all_queries()
for i, rule in enumerate(all_rules, 1):
    print(f"{i:2d}. {rule.rule_id} - {rule.name}")

print(f"\n{'='*60}")
print(f"✅ Total: {len(all_rules)} rules loaded from queries.json")
print(f"{'='*60}")
