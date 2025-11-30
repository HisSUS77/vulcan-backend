"""
Debug script to test the semantic pipeline directly
"""
import asyncio
from semantic_engine.pipeline import get_pipeline, PipelineConfig

async def main():
    # Test code with command injection using known source
    code = """
import os
import sys

def vulnerable_function():
    user_input = sys.argv[1]  # Known source
    os.system(user_input)      # Known sink
    return "executed"
"""
    
    print("Creating pipeline...")
    pipeline = get_pipeline(PipelineConfig(enable_llm=True))
    
    print("Analyzing code...")
    result = await pipeline.analyze_code(
        filename="test.py",
        code=code,
        language="python"
    )
    
    print(f"\n=== RESULTS ===")
    print(f"Graph nodes: {result.graph_nodes}")
    print(f"Graph edges: {result.graph_edges}")
    print(f"Rules executed: {result.rules_executed}")
    print(f"Slices found: {result.slices_found}")
    print(f"Vulnerabilities found: {result.vulnerabilities_found}")
    print(f"Success: {result.success}")
    print(f"Warnings: {result.warnings}")
    print(f"Errors: {result.errors}")
    
    if result.vulnerabilities:
        print(f"\nVulnerabilities:")
        for v in result.vulnerabilities:
            print(f"  - {v['type']}: {v['severity']}")

if __name__ == "__main__":
    asyncio.run(main())
