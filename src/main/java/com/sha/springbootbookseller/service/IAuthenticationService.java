package com.sha.springbootbookseller.service;

import com.sha.springbootbookseller.model.User;

public interface IAuthenticationService {

    com.sha.springbootbookseller.model.User signInAndReturnJWT(User signInRequest);
}
