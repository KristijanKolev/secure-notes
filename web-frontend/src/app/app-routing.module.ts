import { NgModule } from '@angular/core';
import { RouterModule, Routes } from '@angular/router';

const routes: Routes = [
  {
    path: 'auth',
    loadChildren: () => import('src/app/user-management/user-management.module').then(m => m.UserManagementModule)
  },
  {
    path: 'notes',
    loadChildren: () => import('src/app/encrypted-notes/encrypted-notes.module').then(m => m.EncryptedNotesModule)
  },
];

@NgModule({
  imports: [RouterModule.forRoot(routes)],
  exports: [RouterModule]
})
export class AppRoutingModule { }
