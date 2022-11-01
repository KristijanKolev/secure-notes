import { NgModule } from '@angular/core';
import { RouterModule, Routes } from '@angular/router';
import {UserNotesPage} from "./user-notes-page/user-notes.page";

const routes: Routes = [
  {
    path: '',
    component: UserNotesPage
  },
];

@NgModule({
  imports: [RouterModule.forChild(routes)],
  exports: [RouterModule]
})
export class EncryptedNotesRoutingModule { }
