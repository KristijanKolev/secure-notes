import {Component, OnInit} from '@angular/core';
import {ApiService} from "../api.service";
import {ResponsePage} from "../../shared/models/ResponsePage";
import {EncryptedNote} from "../models/EncryptedNote"

@Component({
  selector: 'app-user-notes-page',
  templateUrl: './user-notes.page.html',
  styleUrls: ['./user-notes.page.scss']
})
export class UserNotesPage implements OnInit {

  currentPage: ResponsePage<EncryptedNote> = new ResponsePage<EncryptedNote>();
  currentPageNum: number = 0;
  currentPageSize: number = 10;

  constructor(
    private apiService: ApiService
  ) {
  }

  ngOnInit(): void {
    this.apiService.loadUserNotes(this.currentPageNum, this.currentPageSize)
      .subscribe(response => {
        console.log('Notes: ', response);
        this.currentPage = response;
      });
  }

}
