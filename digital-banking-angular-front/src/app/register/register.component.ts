import { Component, OnInit } from '@angular/core';
import {AuthService} from "../services/auth.service";
import {FormBuilder, FormGroup} from "@angular/forms";


@Component({
  selector: 'app-register',
  templateUrl: './register.component.html',
  styleUrls: ['./register.component.css']
})
export class RegisterComponent implements OnInit {

  formRegister! : FormGroup;

  isSuccessful = false;
  isSignUpFailed = false;
  errorMessage = '';

  constructor(private authService: AuthService, private fb : FormBuilder) { }

  ngOnInit(): void {

    this.formRegister=this.fb.group({
      username : this.fb.control(""),
      password : this.fb.control(""),
      email : this.fb.control("")
    })
  }

  onSubmit(): void {
    let username = this.formRegister.value.username;
    let password = this.formRegister.value.password;
    let email = this.formRegister.value.email;


    this.authService.register(username, email, password).subscribe(
      data => {
        console.log(data);
        this.isSuccessful = true;
        this.isSignUpFailed = false;
      },
      err => {
        this.errorMessage = err.error.message;
        this.isSignUpFailed = true;
      }
    );
  }
}
