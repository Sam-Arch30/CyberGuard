import React from 'react';
import { useParams } from 'react-router-dom';
import { CrossSourceCorrelationView } from '../components/correlation/CrossSourceCorrelationView';

export const CrossSourceCorrelationPage: React.FC = () => {
  const { id } = useParams<{ id?: string }>();
  return <CrossSourceCorrelationView initialCorrelationId={id} />;
};

export default CrossSourceCorrelationPage;
