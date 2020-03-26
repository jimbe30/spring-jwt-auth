package net.jmb.module.security.exception;

import org.springframework.http.HttpStatus;
import org.springframework.security.core.AuthenticationException;

public class InvalidOidcTokenException extends AuthenticationException {

private static final long serialVersionUID = 1L;

  private final HttpStatus httpStatus;
  
  public InvalidOidcTokenException(String message) {
	    super(message);
	    httpStatus = HttpStatus.UNAUTHORIZED;
  }

  public InvalidOidcTokenException(String message, HttpStatus httpStatus) {
    super(message);
    this.httpStatus = httpStatus;
  }

  public HttpStatus getHttpStatus() {
    return httpStatus;
  }

}
