import { SCENARIO_1_LEGITIMATE, SCENARIO_2_PHISHING, SCENARIO_3_PRIMARY_EMAIL } from './sihScenariosData';
import type { EmailAnalysis } from '../../types/forensic';
export function loadDemo(id: string): EmailAnalysis | null {
  const scenarios: Record<string, EmailAnalysis> = {
    'scenario-1-legit': SCENARIO_1_LEGITIMATE,
    'scenario-2-phish': SCENARIO_2_PHISHING,
    'scenario-3-campaign': SCENARIO_3_PRIMARY_EMAIL,
  };
  return scenarios[id] ? {...scenarios[id], is_demo: true} : null;
}
