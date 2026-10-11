import React from 'react';
import { useParams } from 'react-router-dom';
import { AttackSurfaceWorkspaceView } from '../components/attackSurface/AttackSurfaceWorkspaceView';

export const AttackSurfacePage: React.FC = () => {
  const { id } = useParams<{ id?: string }>();
  return <AttackSurfaceWorkspaceView initialAssetId={id} />;
};

export default AttackSurfacePage;
