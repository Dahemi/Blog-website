import React from "react";
import Breaker from "../components/home/breaker/Breaker";
import Posts from "../components/home/post/Posts";
import Navbar from "../components/Navbar";
import Card from "../components/home/card/Card";
import { useState } from "react";
import Footer from "../components/footer/Footer";
function HomePage({ user, category }) {
  const [mpost, setmpost] = useState(category);
  const [flag, setflag] = useState(false);
  return (
    <div className="HomePage">
      <Navbar user={user} />
      <Card setmpost={setmpost} setflag={setflag} flag={flag} mpost={mpost} />
      <Breaker text='Featured Post' />
      <Posts category={category} />
      <Footer />
    </div>
  );
}

export default HomePage;
