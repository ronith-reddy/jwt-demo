package com.example.jwtdemo.constants;

public enum RequestHeader {
    IS_REFRESH_TOKEN("isRefreshToken");

    private final String headerName;

    RequestHeader(String headerName) {
        this.headerName = headerName;
    }

    public String getHeaderName() {
        return headerName;
    }
}
