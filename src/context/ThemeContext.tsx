import React, { createContext, useContext, useEffect, useState } from 'react';

export type AppTheme = 'obsidian' | 'blossom' | 'violet' | 'paper';

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
    id: 'obsidian',
    name: 'Obsidian',
    description: 'Deep stone dark theme with subtle olive green accents',
    accentLabel: 'Olive Green',
    previewBg: '#0c0e0d',
    previewSurface: '#141715',
    previewAccent: '#7d9456',
    isDark: true,
  },
  {
    id: 'blossom',
    name: 'Blossom',
    description: 'Crisp porcelain light surfaces with restrained pastel pink highlights',
    accentLabel: 'Pastel Rose',
    previewBg: '#faf9f9',
    previewSurface: '#ffffff',
    previewAccent: '#c76587',
    isDark: false,
  },
  {
    id: 'violet',
    name: 'Violet',
    description: 'Deep neutral charcoal-purple with technical violet accents',
    accentLabel: 'Refined Violet',
    previewBg: '#0f0e17',
    previewSurface: '#191626',
    previewAccent: '#8374e6',
    isDark: true,
  },
  {
    id: 'paper',
    name: 'Paper',
    description: 'Warm cream dossier background with dark ink typography',
    accentLabel: 'Technical Ink',
    previewBg: '#f6f3eb',
    previewSurface: '#fdfbf7',
    previewAccent: '#7a5f45',
    isDark: false,
  },
];

interface ThemeContextType {
  theme: AppTheme;
  setTheme: (theme: AppTheme) => void;
  isDark: boolean;
  themeMeta: ThemeOption;
}

const STORAGE_KEY = 'mailtrace_theme';
const DEFAULT_THEME: AppTheme = 'obsidian';

const ThemeContext = createContext<ThemeContextType | undefined>(undefined);

export const ThemeProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [theme, setThemeState] = useState<AppTheme>(() => {
    try {
      const stored = localStorage.getItem(STORAGE_KEY);
      if (stored && ['obsidian', 'blossom', 'violet', 'paper'].includes(stored)) {
        return stored as AppTheme;
      }
    } catch {
      // Fallback on restricted storage environments
    }
    return DEFAULT_THEME;
  });

  const setTheme = (newTheme: AppTheme) => {
    setThemeState(newTheme);
    try {
      localStorage.setItem(STORAGE_KEY, newTheme);
    } catch {
      // Ignore storage errors
    }
  };

  useEffect(() => {
    const root = document.documentElement;
    root.setAttribute('data-theme', theme);
    const activeMeta = THEME_OPTIONS.find((t) => t.id === theme) || THEME_OPTIONS[0];
    if (activeMeta.isDark) {
      root.classList.add('dark');
    } else {
      root.classList.remove('dark');
    }
  }, [theme]);

  const currentMeta = THEME_OPTIONS.find((t) => t.id === theme) || THEME_OPTIONS[0];

  return (
    <ThemeContext.Provider
      value={{
        theme,
        setTheme,
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
