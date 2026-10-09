import React, { createContext, useContext, useEffect, useState, useMemo } from 'react';

export type AppTheme = 'olive' | 'sakura' | 'paper' | 'midnight';
export type ThemePreference = AppTheme | 'system';

export interface ThemeOption {
  id: AppTheme;
  name: string;
  description: string;
  accentLabel: string;
  previewBg: string;
  previewSurface: string;
  previewAccent: string;
  isDark: boolean;
}

export const THEME_OPTIONS: ThemeOption[] = [
  {
    id: 'olive',
    name: 'Olive',
    description: 'Primary CyberGuard SOC identity: near-black graphite with organic muted olive accents',
    accentLabel: 'Muted Olive',
    previewBg: '#090a08',
    previewSurface: '#11130f',
    previewAccent: '#7d9456',
    isDark: true,
  },
  {
    id: 'sakura',
    name: 'Sakura',
    description: 'Refined porcelain light surfaces with restrained soft pink accents and high-contrast typography',
    accentLabel: 'Soft Sakura',
    previewBg: '#faf8f9',
    previewSurface: '#ffffff',
    previewAccent: '#c26382',
    isDark: false,
  },
  {
    id: 'paper',
    name: 'Paper',
    description: 'Warm ivory editorial dossier background with ink black typography and fine warm borders',
    accentLabel: 'Technical Brown',
    previewBg: '#f5f2e9',
    previewSurface: '#fcfaf5',
    previewAccent: '#725b44',
    isDark: false,
  },
  {
    id: 'midnight',
    name: 'Midnight',
    description: 'Cool technical dark theme with graphite surfaces and controlled electric cyan accents',
    accentLabel: 'Electric Cyan',
    previewBg: '#0a0c10',
    previewSurface: '#12151c',
    previewAccent: '#2fa5c4',
    isDark: true,
  },
];

interface ThemeContextType {
  theme: AppTheme;
  themePreference: ThemePreference;
  setTheme: (theme: AppTheme) => void;
  setThemePreference: (pref: ThemePreference) => void;
  isDark: boolean;
  themeMeta: ThemeOption;
}

const STORAGE_KEY = 'cyberguard_theme';
const LEGACY_STORAGE_KEY = 'mailtrace_theme';
const DEFAULT_THEME: AppTheme = 'olive';

function normalizeTheme(raw: string | null): AppTheme {
  if (!raw) return DEFAULT_THEME;
  if (raw === 'olive' || raw === 'sakura' || raw === 'paper' || raw === 'midnight') {
    return raw as AppTheme;
  }
  // Backward-compatibility aliases
  if (raw === 'obsidian') return 'olive';
  if (raw === 'blossom') return 'sakura';
  if (raw === 'violet') return 'midnight';
  return DEFAULT_THEME;
}

const ThemeContext = createContext<ThemeContextType | undefined>(undefined);

export const ThemeProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [themePreference, setThemePreferenceState] = useState<ThemePreference>(() => {
    try {
      const stored = localStorage.getItem(STORAGE_KEY) || localStorage.getItem(LEGACY_STORAGE_KEY);
      if (stored === 'system') return 'system';
      return normalizeTheme(stored);
    } catch {
      return DEFAULT_THEME;
    }
  });

  const [systemIsDark, setSystemIsDark] = useState<boolean>(() => {
    if (typeof window !== 'undefined' && window.matchMedia) {
      return window.matchMedia('(prefers-color-scheme: dark)').matches;
    }
    return true;
  });

  // Track system OS color scheme changes
  useEffect(() => {
    if (typeof window === 'undefined' || !window.matchMedia) return;
    const media = window.matchMedia('(prefers-color-scheme: dark)');
    const handler = (e: MediaQueryListEvent) => setSystemIsDark(e.matches);
    media.addEventListener('change', handler);
    return () => media.removeEventListener('change', handler);
  }, []);

  // Compute effective active theme
  const effectiveTheme: AppTheme = useMemo(() => {
    if (themePreference === 'system') {
      return systemIsDark ? 'olive' : 'paper';
    }
    return themePreference;
  }, [themePreference, systemIsDark]);

  const setTheme = (newTheme: AppTheme) => {
    setThemePreferenceState(newTheme);
    try {
      localStorage.setItem(STORAGE_KEY, newTheme);
      localStorage.setItem(LEGACY_STORAGE_KEY, newTheme);
    } catch {
      // Ignore storage errors in restricted environments
    }
  };

  const setThemePreference = (pref: ThemePreference) => {
    setThemePreferenceState(pref);
    try {
      localStorage.setItem(STORAGE_KEY, pref);
    } catch {
      // Ignore storage errors
    }
  };

  useEffect(() => {
    const root = document.documentElement;
    root.setAttribute('data-theme', effectiveTheme);
    const activeMeta = THEME_OPTIONS.find((t) => t.id === effectiveTheme) || THEME_OPTIONS[0];
    if (activeMeta.isDark) {
      root.classList.add('dark');
    } else {
      root.classList.remove('dark');
    }
  }, [effectiveTheme]);

  const currentMeta = THEME_OPTIONS.find((t) => t.id === effectiveTheme) || THEME_OPTIONS[0];

  return (
    <ThemeContext.Provider
      value={{
        theme: effectiveTheme,
        themePreference,
        setTheme,
        setThemePreference,
        isDark: currentMeta.isDark,
        themeMeta: currentMeta,
      }}
    >
      {children}
    </ThemeContext.Provider>
  );
};

export const useTheme = (): ThemeContextType => {
  const context = useContext(ThemeContext);
  if (!context) {
    throw new Error('useTheme must be used within a ThemeProvider');
  }
  return context;
};
