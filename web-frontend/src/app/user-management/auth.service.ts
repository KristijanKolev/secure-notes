import {Injectable} from '@angular/core';
import {HttpClient} from "@angular/common/http";
import {TokenInfo} from "./models/TokenInfo";
import {BehaviorSubject, Observable} from "rxjs";
import {tap} from "rxjs/operators";
import {Router} from "@angular/router";


const AUTH_API_URL = 'api/auth/';


@Injectable({
  providedIn: 'root'
})
export class AuthService {
  public accessToken: any;
  public refreshToken: any;
  public accessTokenInfo?: TokenInfo;
  public accessTokenInfo$: BehaviorSubject<any>;
  private refreshTimeout?: NodeJS.Timeout;


  constructor(
    private httpClient: HttpClient,
    private router: Router
  ) {
    this.accessTokenInfo$ = new BehaviorSubject({});
  }

  login(username: string, password: string): Observable<any> {
    return this.httpClient.post(AUTH_API_URL + 'token/', {username, password}, {withCredentials: true}).pipe(
        tap(resp => this.handleAuthResponse(resp))
      );
  }

  refreshAuth(): Observable<any> {
    return this.httpClient.post(AUTH_API_URL + 'token/refresh/', {}, {withCredentials: true}).pipe(
        tap(resp => this.handleAuthResponse(resp))
      );
  }

  public logout(): Observable<any> {
    // Must call lougout endpoint to clear http-only cookie.
    return this.httpClient.post(AUTH_API_URL + 'logout/', {}, {withCredentials: true}).pipe(
        tap(() => {
          this.clearAuthInfo();
          clearTimeout(this.refreshTimeout);
        })
      );
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
