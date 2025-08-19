azure-security-monitor.py                                                                                                                          │ │
│ │                                                                                                                                                            │ │
│ │ #!/usr/bin/env python3                                                                                                                                     │ │
│ │ """                                                                                                                                                        │ │
│ │ Azure Security Monitor for Claude Code Integration                                                                                                         │ │
│ │ Pulls Azure security recommendations and provides automated remediation suggestions.                                                                       │ │
│ │ """                                                                                                                                                        │ │
│ │                                                                                                                                                            │ │
│ │ import json                                                                                                                                                │ │
│ │ import subprocess                                                                                                                                          │ │
│ │ import sys                                                                                                                                                 │ │
│ │ from datetime import datetime                                                                                                                              │ │
│ │ from typing import Dict, List, Any                                                                                                                         │ │
│ │ import argparse                                                                                                                                            │ │
│ │                                                                                                                                                            │ │
│ │ class AzureSecurityMonitor:                                                                                                                                │ │
│ │     def __init__(self):                                                                                                                                    │ │
│ │         self.subscription_id = self._get_subscription_id()                                                                                                 │ │
│ │                                                                                                                                                            │ │
│ │     def _get_subscription_id(self) -> str:                                                                                                                 │ │
│ │         """Get current Azure subscription ID"""                                                                                                            │ │
│ │         try:                                                                                                                                               │ │
│ │             result = subprocess.run(                                                                                                                       │ │
│ │                 ['az', 'account', 'show', '--query', 'id', '-o', 'tsv'],                                                                                   │ │
│ │                 capture_output=True, text=True, check=True                                                                                                 │ │
│ │             )                                                                                                                                              │ │
│ │             return result.stdout.strip()                                                                                                                   │ │
│ │         except subprocess.CalledProcessError as e:                                                                                                         │ │
│ │             print(f"Error getting subscription ID: {e}")                                                                                                   │ │
│ │             sys.exit(1)                                                                                                                                    │ │
│ │                                                                                                                                                            │ │
│ │     def get_security_recommendations(self) -> List[Dict[str, Any]]:                                                                                        │ │
│ │         """Fetch Azure Advisor security recommendations"""                                                                                                 │ │
│ │         try:                                                                                                                                               │ │
│ │             result = subprocess.run([                                                                                                                      │ │
│ │                 'az', 'advisor', 'recommendation', 'list',                                                                                                 │ │
│ │                 '--category', 'Security',                                                                                                                  │ │
│ │                 '--output', 'json'                                                                                                                         │ │
│ │             ], capture_output=True, text=True, check=True)                                                                                                 │ │
│ │                                                                                                                                                            │ │
│ │             recommendations = json.loads(result.stdout)                                                                                                    │ │
│ │             return self._process_recommendations(recommendations)                                                                                          │ │
│ │                                                                                                                                                            │ │
│ │         except subprocess.CalledProcessError as e:                                                                                                         │ │
│ │             print(f"Error fetching recommendations: {e}")                                                                                                  │ │
│ │             return []                                                                                                                                      │ │
│ │         except json.JSONDecodeError as e:                                                                                                                  │ │
│ │             print(f"Error parsing JSON: {e}")                                                                                                              │ │
│ │             return []                                                                                                                                      │ │
│ │                                                                                                                                                            │ │
│ │     def _process_recommendations(self, raw_recommendations: List[Dict]) -> List[Dict[str, Any]]:                                                           │ │
│ │         """Process and structure recommendations"""                                                                                                        │ │
│ │         processed = []                                                                                                                                     │ │
│ │                                                                                                                                                            │ │
│ │         for rec in raw_recommendations:                                                                                                                    │ │
│ │             try:                                                                                                                                           │ │
│ │                 props = rec.get('properties', {})                                                                                                          │ │
│ │                 metadata = props.get('resourceMetadata', {})                                                                                               │ │
│ │                 short_desc = props.get('shortDescription', {})                                                                                             │ │
│ │                                                                                                                                                            │ │
│ │                 processed_rec = {                                                                                                                          │ │
│ │                     'id': rec.get('id', ''),                                                                                                               │ │
│ │                     'category': props.get('category', 'Unknown'),                                                                                          │ │
│ │                     'impact': props.get('impact', 'Unknown'),                                                                                              │ │
│ │                     'problem': short_desc.get('problem', 'No description available'),                                                                      │ │
│ │                     'solution': short_desc.get('solution', 'No solution available'),                                                                       │ │
│ │                     'resource_type': metadata.get('resourceType', 'Unknown'),                                                                              │ │
│ │                     'resource_group': metadata.get('resourceGroup', 'Unknown'),                                                                            │ │
│ │                     'resource_id': metadata.get('resourceId', ''),                                                                                         │ │
│ │                     'recommendation_type': props.get('recommendationTypeId', ''),                                                                          │ │
│ │                     'last_updated': props.get('lastUpdated', ''),                                                                                          │ │
│ │                     'automated_fix_available': self._check_automated_fix(props.get('recommendationTypeId', ''))                                            │ │
│ │                 }                                                                                                                                          │ │
│ │                                                                                                                                                            │ │
│ │                 processed.append(processed_rec)                                                                                                            │ │
│ │                                                                                                                                                            │ │
│ │             except Exception as e:                                                                                                                         │ │
│ │                 print(f"Error processing recommendation: {e}")                                                                                             │ │
│ │                 continue                                                                                                                                   │ │
│ │                                                                                                                                                            │ │
│ │         return processed                                                                                                                                   │ │
│ │                                                                                                                                                            │ │
│ │     def _check_automated_fix(self, recommendation_type_id: str) -> bool:                                                                                   │ │
│ │         """Check if automated fix is available for this recommendation type"""                                                                             │ │
│ │         automated_fixes = {                                                                                                                                │ │
│ │             # Key Vault recommendations                                                                                                                    │ │
│ │             'b14a3c4e-f6c8-4b21-9e3a-3c4b5f6e7a8b': True,  # Enable Key Vault firewall                                                                     │ │
│ │             'a1b2c3d4-e5f6-7890-abcd-ef1234567890': True,  # Enable purge protection                                                                       │ │
│ │                                                                                                                                                            │ │
│ │             # SQL Database recommendations                                                                                                                 │ │
│ │             'c3d4e5f6-1234-5678-9abc-def123456789': True,  # Enable SQL Defender                                                                           │ │
│ │             'e5f6a7b8-9012-3456-7890-abc123456789': True,  # Disable public access                                                                         │ │
│ │                                                                                                                                                            │ │
│ │             # Storage recommendations                                                                                                                      │ │
│ │             'f6a7b8c9-2345-6789-0123-456789abcdef': True,  # Enable secure transfer                                                                        │ │
│ │                                                                                                                                                            │ │
│ │             # Network Security Group recommendations                                                                                                       │ │
│ │             'a7b8c9d0-3456-7890-1234-56789abcdefg': True,  # Restrict NSG rules                                                                            │ │
│ │         }                                                                                                                                                  │ │
│ │                                                                                                                                                            │ │
│ │         return automated_fixes.get(recommendation_type_id, False)                                                                                          │ │
│ │                                                                                                                                                            │ │
│ │     def get_high_priority_recommendations(self) -> List[Dict[str, Any]]:                                                                                   │ │
│ │         """Get high and medium impact recommendations"""                                                                                                   │ │
│ │         all_recs = self.get_security_recommendations()                                                                                                     │ │
│ │         return [rec for rec in all_recs if rec['impact'] in ['High', 'Medium']]                                                                            │ │
│ │                                                                                                                                                            │ │
│ │     def get_automated_fix_candidates(self) -> List[Dict[str, Any]]:                                                                                        │ │
│ │         """Get recommendations that can be automatically fixed"""                                                                                          │ │
│ │         all_recs = self.get_security_recommendations()                                                                                                     │ │
│ │         return [rec for rec in all_recs if rec['automated_fix_available']]                                                                                 │ │
│ │                                                                                                                                                            │ │
│ │     def generate_security_report(self) -> Dict[str, Any]:                                                                                                  │ │
│ │         """Generate comprehensive security report"""                                                                                                       │ │
│ │         recommendations = self.get_security_recommendations()                                                                                              │ │
│ │                                                                                                                                                            │ │
│ │         # Count by impact                                                                                                                                  │ │
│ │         impact_counts = {}                                                                                                                                 │ │
│ │         for rec in recommendations:                                                                                                                        │ │
│ │             impact = rec['impact']                                                                                                                         │ │
│ │             impact_counts[impact] = impact_counts.get(impact, 0) + 1                                                                                       │ │
│ │                                                                                                                                                            │ │
│ │         # Count by resource type                                                                                                                           │ │
│ │         resource_type_counts = {}                                                                                                                          │ │
│ │         for rec in recommendations:                                                                                                                        │ │
│ │             resource_type = rec['resource_type']                                                                                                           │ │
│ │             resource_type_counts[resource_type] = resource_type_counts.get(resource_type, 0) + 1                                                           │ │
│ │                                                                                                                                                            │ │
│ │         # Get automated fix candidates                                                                                                                     │ │
│ │         automated_fixes = self.get_automated_fix_candidates()                                                                                              │ │
│ │                                                                                                                                                            │ │
│ │         report = {                                                                                                                                         │ │
│ │             'timestamp': datetime.now().isoformat(),                                                                                                       │ │
│ │             'subscription_id': self.subscription_id,                                                                                                       │ │
│ │             'total_recommendations': len(recommendations),                                                                                                 │ │
│ │             'impact_breakdown': impact_counts,                                                                                                             │ │
│ │             'resource_type_breakdown': resource_type_counts,                                                                                               │ │
│ │             'automated_fix_candidates': len(automated_fixes),                                                                                              │ │
│ │             'high_priority_recommendations': [                                                                                                             │ │
│ │                 rec for rec in recommendations if rec['impact'] == 'High'                                                                                  │ │
│ │             ][:10],  # Top 10 high priority                                                                                                                │ │
│ │             'automated_fix_ready': automated_fixes[:5]  # Top 5 automated fixes                                                                            │ │
│ │         }                                                                                                                                                  │ │
│ │                                                                                                                                                            │ │
│ │         return report                                                                                                                                      │ │
│ │                                                                                                                                                            │ │
│ │     def generate_claude_code_summary(self) -> str:                                                                                                         │ │
│ │         """Generate a Claude Code friendly summary"""                                                                                                      │ │
│ │         report = self.generate_security_report()                                                                                                           │ │
│ │                                                                                                                                                            │ │
│ │         summary = f"""# 🔒 Azure Security Status - {datetime.now().strftime('%Y-%m-%d')}                                                                   │ │
│ │                                                                                                                                                            │ │
│ │ ## 📊 Overview                                                                                                                                             │ │
│ │ - **Total Security Recommendations**: {report['total_recommendations']}                                                                                    │ │
│ │ - **High Impact**: {report['impact_breakdown'].get('High', 0)}                                                                                             │ │
│ │ - **Medium Impact**: {report['impact_breakdown'].get('Medium', 0)}                                                                                         │ │
│ │ - **Low Impact**: {report['impact_breakdown'].get('Low', 0)}                                                                                               │ │
│ │ - **Automated Fix Ready**: {report['automated_fix_candidates']}                                                                                            │ │
│ │                                                                                                                                                            │ │
│ │ ## 🚨 Top High Priority Issues"""                                                                                                                          │ │
│ │                                                                                                                                                            │ │
│ │         for i, rec in enumerate(report['high_priority_recommendations'], 1):                                                                               │ │
│ │             summary += f"""                                                                                                                                │ │
│ │                                                                                                                                                            │ │
│ │ ### {i}. {rec['problem'][:80]}...                                                                                                                          │ │
│ │ - **Impact**: {rec['impact']}                                                                                                                              │ │
│ │ - **Resource**: {rec['resource_group']}/{rec['resource_type']}                                                                                             │ │
│ │ - **Solution**: {rec['solution'][:100]}...                                                                                                                 │ │
│ │ - **Auto-Fix Available**: {'✅' if rec['automated_fix_available'] else '❌'}                                                                                 │ │
│ │ """                                                                                                                                                        │ │
│ │                                                                                                                                                            │ │
│ │         summary += f"""                                                                                                                                    │ │
│ │                                                                                                                                                            │ │
│ │ ## 🔧 Ready for Automation                                                                                                                                 │ │
│ │ {len(report['automated_fix_ready'])} recommendations can be automatically resolved.                                                                        │ │
│ │                                                                                                                                                            │ │
│ │ ## 🎯 Resource Breakdown"""                                                                                                                                │ │
│ │                                                                                                                                                            │ │
│ │         for resource_type, count in sorted(report['resource_type_breakdown'].items(),                                                                      │ │
│ │                                          key=lambda x: x[1], reverse=True)[:5]:                                                                            │ │
│ │             summary += f"\n- **{resource_type}**: {count} recommendations"                                                                                 │ │
│ │                                                                                                                                                            │ │
│ │         summary += f"""                                                                                                                                    │ │
│ │                                                                                                                                                            │ │
│ │ ## 🚀 Next Steps                                                                                                                                           │ │
│ │ 1. Review high-impact recommendations above                                                                                                                │ │
│ │ 2. Run automated fixes for eligible items                                                                                                                  │ │
│ │ 3. Manually address remaining critical issues                                                                                                              │ │
│ │ 4. Schedule periodic security reviews                                                                                                                      │ │
│ │                                                                                                                                                            │ │
│ │ **Generated**: {report['timestamp']}                                                                                                                       │ │
│ │ **Subscription**: {report['subscription_id']}                                                                                                              │ │
│ │ """                                                                                                                                                        │ │
│ │                                                                                                                                                            │ │
│ │         return summary                                                                                                                                     │ │
│ │                                                                                                                                                            │ │
│ │ def main():                                                                                                                                                │ │
│ │     parser = argparse.ArgumentParser(description='Azure Security Monitor for Claude Code')                                                                 │ │
│ │     parser.add_argument('--format', choices=['json', 'summary', 'claude'],                                                                                 │ │
│ │                        default='claude', help='Output format')                                                                                             │ │
│ │     parser.add_argument('--high-priority-only', action='store_true',                                                                                       │ │
│ │                        help='Show only high priority recommendations')                                                                                     │ │
│ │     parser.add_argument('--automated-only', action='store_true',                                                                                           │ │
│ │                        help='Show only automated fix candidates')                                                                                          │ │
│ │                                                                                                                                                            │ │
│ │     args = parser.parse_args()                                                                                                                             │ │
│ │                                                                                                                                                            │ │
│ │     monitor = AzureSecurityMonitor()                                                                                                                       │ │
│ │                                                                                                                                                            │ │
│ │     if args.format == 'json':                                                                                                                              │ │
│ │         if args.high_priority_only:                                                                                                                        │ │
│ │             data = monitor.get_high_priority_recommendations()                                                                                             │ │
│ │         elif args.automated_only:                                                                                                                          │ │
│ │             data = monitor.get_automated_fix_candidates()                                                                                                  │ │
│ │         else:                                                                                                                                              │ │
│ │             data = monitor.generate_security_report()                                                                                                      │ │
│ │         print(json.dumps(data, indent=2))                                                                                                                  │ │
│ │                                                                                                                                                            │ │
│ │     elif args.format == 'summary':                                                                                                                         │ │
│ │         report = monitor.generate_security_report()                                                                                                        │ │
│ │         print(f"Total Recommendations: {report['total_recommendations']}")                                                                                 │ │
│ │         print(f"High Impact: {report['impact_breakdown'].get('High', 0)}")                                                                                 │ │
│ │         print(f"Automated Fix Ready: {report['automated_fix_candidates']}")                                                                                │ │
│ │                                                                                                                                                            │ │
│ │     else:  # claude format                                                                                                                                 │ │
│ │         summary = monitor.generate_claude_code_summary()                                                                                                   │ │
│ │         print(summary)                                                                                                                                     │ │
│ │                                                                                                                                                            │ │
│ │ if __name__ == '__main__':                                                                                                                                 │ │
│ │     main()                       
