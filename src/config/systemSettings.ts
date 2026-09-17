import type { SystemSettings } from '../types';

export const INITIAL_SETTINGS: SystemSettings = {
  anonymizeTargetPII: true,
  maskEmailAddresses: false,
  retentionPeriodDays: 90,
  autoEscalateThreshold: 85,
  sha256ChainOfCustody: true,
  enableRealTimeAlerts: true,
  webhookUrl: '',
  allowedIpSubnets: '10.0.0.0/8, 172.16.0.0/12'
};
