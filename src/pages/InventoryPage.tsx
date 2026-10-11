import React from 'react';
import { useParams, useLocation } from 'react-router-dom';
import { InventoryWorkspaceView } from '../components/inventory/InventoryWorkspaceView';

export const InventoryPage: React.FC = () => {
  const { id } = useParams<{ id?: string }>();
  const location = useLocation();

  const getInitialTab = (): 'assets' | 'identities' | 'sources' | 'conflicts' => {
    if (location.pathname.startsWith('/identities')) return 'identities';
    if (location.pathname.startsWith('/conflicts')) return 'conflicts';
    if (location.pathname.startsWith('/sources')) return 'sources';
    return 'assets';
  };

  return <InventoryWorkspaceView initialAssetId={id} initialTab={getInitialTab()} />;
};

export default InventoryPage;
