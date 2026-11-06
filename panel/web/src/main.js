import { mount } from 'svelte';
import './app.css';
import App from './App.svelte';

try {
  const t = localStorage.getItem('theme');
  if (t) document.documentElement.dataset.theme = t;
} catch {
  /* kein Speicher */
}

mount(App, { target: document.getElementById('app') });
