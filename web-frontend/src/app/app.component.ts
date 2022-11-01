import {Component, OnInit} from '@angular/core';
import {AuthService} from "./user-management/auth.service";

@Component({
  selector: 'app-root',
  templateUrl: './app.component.html',
  styleUrls: ['./app.component.scss']
})
export class AppComponent implements OnInit{
  title = 'web-frontend';

  constructor(
    private authService: AuthService
  ) { }


  async ngOnInit() {
    await this.authService.refreshAuth().toPromise();
  }


}
