import { provideZoneChangeDetection } from '@angular/core';
import { bootstrapApplication } from '@angular/platform-browser';
import { AppComponent } from './app/app.component';

if (window.self !== window.top) {
  document.body.textContent = 'Open Password Manager directly in its own browser tab.';
} else {
  bootstrapApplication(AppComponent, {
    providers: [provideZoneChangeDetection()],
  }).catch(err => console.error(err));
}
