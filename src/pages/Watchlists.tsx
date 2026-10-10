import React, { useState, useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { Eye } from 'lucide-react';
import { WatchlistList } from '../components/watchlists/WatchlistList';
import { WatchlistDetailView } from '../components/watchlists/WatchlistDetailView';
import { WatchlistService } from '../services/watchlistService';
import type { WatchlistSummary } from '../types/watchlist';

export const Watchlists: React.FC = () => {
  const { id } = useParams<{ id?: string }>();
  const navigate = useNavigate();

  const [watchlists, setWatchlists] = useState<WatchlistSummary[]>([]);
  const [loading, setLoading] = useState(true);

  const loadWatchlists = async () => {
    try {
      setLoading(true);
      const res = await WatchlistService.listWatchlists({ limit: 100 });
      setWatchlists(res.items);
    } catch (err) {
      console.error('Failed to load watchlists:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadWatchlists();
  }, []);

  return (
    <div className="p-4 md:p-6 space-y-6 max-w-7xl mx-auto">
      {/* Page Title & Navigation Banner */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-border pb-4">
        <div>
          <h1 className="text-xl font-bold text-foreground flex items-center space-x-2">
            <Eye className="w-5 h-5 text-primary" />
            <span>IOC Watchlists & Continuous Monitoring</span>
          </h1>
          <p className="text-xs text-foreground-muted mt-1">
            Section 53: Continuous threat intelligence polling, material change detection, and automated security alerting.
          </p>
        </div>
      </div>

      {/* Main Content Area */}
      {id ? (
        <WatchlistDetailView
          watchlistId={id}
          onBack={() => navigate('/watchlists')}
        />
      ) : (
        <WatchlistList
          watchlists={watchlists}
          loading={loading}
          onSelectWatchlist={(selectedId) => navigate(`/watchlists/${selectedId}`)}
          onRefreshList={loadWatchlists}
        />
      )}
    </div>
  );
};
