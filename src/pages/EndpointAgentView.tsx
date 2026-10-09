import React from 'react';
import { EndpointAgentManager } from '../components/endpoint/EndpointAgentManager';

export const EndpointAgentView: React.FC = () => {
  return (
    <div className="container mx-auto px-4 py-6 max-w-7xl">
      <EndpointAgentManager />
    </div>
  );
};
