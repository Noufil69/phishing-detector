package com.noufil.phishingdetector.controller;

/**
 * The submitted text cannot be checked. The message is written for the person who
 * typed it, and it never repeats the submitted text back.
 */
public class InvalidUrlException extends RuntimeException {

    public InvalidUrlException(String message) {
        super(message);
    }
}