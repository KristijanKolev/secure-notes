import { Injectable } from '@angular/core';
import {HttpClient} from "@angular/common/http";
import {environment} from "../../environments/environment";
import {TokenInfo} from "./models/TokenInfo";
import { tap } from 'rxjs/operators'
import {BehaviorSubject, Observable} from "rxjs";
import {Router} from "@angular/router";


const AUTH_API = 'api/auth/'


@Injectable({
  providedIn: 'root'
})
export class AuthService {
  private accessToken: any;
  private refreshToken: any;
  private accessTokenInfo?: TokenInfo;
  private refreshTimeout?: NodeJS.Timeout;
  public accessTokenInfo$: BehaviorSubject<any>;


  constructor(
    private httpClient: HttpClient,
    private router: Router
  ) {
    this.accessTokenInfo$ = new BehaviorSubject({});
  }

  login(username: string, password: string): void {
    this.httpClient.post(AUTH_API + 'token/', {username, password}, {withCredentials: true})
      .subscribe(resp => this.handleAuthResponse(resp));
  }

  refreshAuth(): void {
    this.httpClient.post(AUTH_API + 'token/refresh/', {}, {withCredentials: true})
      .subscribe(resp => this.handleAuthResponse(resp));
  }

  public logout() {
    // Must call lougout endpoint to clear http-only cookie.
    this.httpClient.post(AUTH_API + 'logout/', {}, {withCredentials: true})
      .subscribe(() => this.clearAuthInfo());

  }

  private clearAuthInfo() {
    this.accessToken = undefined;
    this.refreshToken = undefined;
    this.accessTokenInfo = undefined
    this.accessTokenInfo$.next(undefined);
    this.router.navigate(['/auth/login']).then();
  }

  private handleAuthResponse(response: any) {
    this.accessToken = response.access;
    this.refreshToken = response.refresh;
    this.accessTokenInfo = JSON.parse(atob(response.access.split('.')[1]));
    this.accessTokenInfo$.next(this.accessTokenInfo);
    this.startRefreshAuthTimeout(this.accessTokenInfo);
  }

  private startRefreshAuthTimeout(accessTokenInfo: any) {
    const expires = new Date(accessTokenInfo.exp * 1000);
    // set a timeout to refresh the token 5 minutes before it expires
    const refreshIn = expires.getTime() - Date.now() - (5 * 60 * 1000);
    console.log('Refreshing in ', refreshIn);
    this.refreshTimeout = setTimeout(() => this.refreshAuth(), refreshIn);
  }

}
