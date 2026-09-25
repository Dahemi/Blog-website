import React from "react";
import ReactDOM from "react-dom/client";
import "./index.css";
import App from "./App";
import { BrowserRouter } from "react-router-dom";
import { Provider } from "react-redux";
import { createStore, applyMiddleware } from "redux";
import { composeWithDevTools } from "@redux-devtools/extension";
import rootReducer from "./reducers";
import { setupAxiosInterceptors } from "./helpers/interceptor";

const store = createStore(rootReducer, composeWithDevTools());

// [CWE-613] Fix: attach the 401 -> refresh -> retry interceptor once, globally. It sits on
// the default axios object so every existing axios call in the app is covered without
// having to migrate ~40 call sites to a shared instance.
setupAxiosInterceptors(store);

const root = ReactDOM.createRoot(document.getElementById("root"));
root.render(
  <Provider store={store}>
    <BrowserRouter>
      <App />
    </BrowserRouter>
  </Provider>,
);
