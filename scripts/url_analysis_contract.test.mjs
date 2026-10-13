import test from 'node:test';
import assert from 'node:assert/strict';
import { adaptUrlAnalysis } from '../src/utils/urlAnalysisContract.ts';

test('actual URL pipeline payload maps score, domain and findings', () => {
  const result = adaptUrlAnalysis({target:'https://example.com/a', overall_score:50, overall_severity:'MEDIUM', confidence:.7,
    analyzer_metadata:{passive_url_analyzer:{parsed_components:{hostname:'example.com'}}},
    findings:[{finding_type:'LOOKALIKE_DOMAIN',title:'Lookalike',description:'Reference mismatch',severity:'MEDIUM',confidence:.7}]});
  assert.equal(result.overall_risk_score,50);
  assert.equal(result.domain,'example.com');
  assert.equal(result.findings.length,1);
  assert.equal(result.is_lookalike,true);
  assert.equal(result.domain_age_days,undefined);
  assert.equal(result.redirect_hops_count,null);
});
test('zero results remain unverified and malformed scores reject', () => {
  assert.equal(adaptUrlAnalysis({target:'https://example.com/',overall_score:0,findings:[]}).confidence,0);
  for (const score of [undefined,NaN,Infinity,-1,101,'50']) assert.throws(()=>adaptUrlAnalysis({overall_score:score,findings:[]}));
});
