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

// Abfragen im Hintergrund (Live-Werte, Listen) schlagen fehl, solange der Server neu startet –
// das ist kein Fehler der Oberfläche; die nächste Abfrage holt den Stand nach.
window.addEventListener('unhandledrejection', (ev) => {
  if (ev.reason?.offline) ev.preventDefault();
});
