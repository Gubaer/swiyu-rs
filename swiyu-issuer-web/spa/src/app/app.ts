import { Component } from '@angular/core';
import { RouterOutlet } from '@angular/router';

import { TopBar } from './layout/top-bar';
import { Sidebar } from './layout/sidebar';

@Component({
  selector: 'app-root',
  imports: [RouterOutlet, TopBar, Sidebar],
  templateUrl: './app.html',
  styleUrl: './app.scss'
})
export class App {}
