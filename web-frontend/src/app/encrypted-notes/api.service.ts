import { Injectable } from '@angular/core';
import {HttpClient} from "@angular/common/http";
import {ResponsePage} from "../shared/models/ResponsePage";
import {Observable} from "rxjs";
import {EncryptedNote} from "./models/EncryptedNote";


const API_URL = 'api/';


@Injectable({
  providedIn: 'root'
})
export class ApiService {

  constructor(
    private httpClient: HttpClient
  ) { }

  /**
   * Loads all notes for the authenticated user in a paged response.
   */
  public loadUserNotes(pageNum?: number, pageSize?: number): Observable<ResponsePage<EncryptedNote>> {
    let requestUrl = API_URL + 'notes/' + this.constructPagingQueryParams(pageNum, pageSize);
    return this.httpClient.get(requestUrl, {withCredentials: true});
  }

  private constructPagingQueryParams(pageNum?: number, pageSize?: number): string {
    let queryParams = [];
    if (pageNum) {
      queryParams.push(`page=${pageNum}`);
    }
    if (pageSize) {
      queryParams.push(`page_size=${pageSize}`);
    }
    return queryParams.length ? '?' + queryParams.join('&') : '';
  }
}
