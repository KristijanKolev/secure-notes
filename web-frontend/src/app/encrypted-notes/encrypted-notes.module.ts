import { NgModule } from '@angular/core';
import { CommonModule } from '@angular/common';

import { EncryptedNotesRoutingModule } from './encrypted-notes-routing.module';
import { UserNotesPage } from './user-notes-page/user-notes.page';
import {SharedModule} from "../shared/shared.module";


@NgModule({
  declarations: [
    UserNotesPage
  ],
  imports: [
    CommonModule,
    EncryptedNotesRoutingModule,
    SharedModule
  ]
})
export class EncryptedNotesModule { }
