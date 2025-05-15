<h1> 2024-2 한림대학교 캡스톤 디자인 프로젝트 </h1>
</br>

# 💻 프로젝트명
### 인공지능을 활용한 통합 보안 솔루션 (UTM) 사이트

</br>

# 📝 프로젝트 소개
### 계기

<p>
한국인터넷진흥원에서 발표한 사이버 위협 동향을 통해 근 4년간 DDoS 공격 신고 건수가 2배 이상 늘었다는 사실을 접하게 되었다. </br>
이러한 사실을 알고 DDoS로 인한 피해를 줄일 수 있는 방법에 대해 고민해보게 되었다. </br>
그러던 중 최근 부상하고 있는 AI기술을 방화벽에 접목한다면 좋은 결과물이 나올 수 있다고 생각해보게 되었고, 딥러닝 모델을 이용한다면 정상적인 트래픽 흐름의 특징을 추출한 뒤에 이를 통해 트래픽의 흐름을 예측 가능할 것이고 이와 비교하여 악의적인 트래픽, 즉 DDoS와 같은 공격을 감지할 수 있을 것이라 생각하였다. </br>
이후 iptables와 같은 방화벽 도구들을 이용한다면 자동으로 공격을 탐지 및 차단할 수 있지 않을까 라는 생각에 해당 프로젝트를 시작하게 되었다. </br>
</p>
</br>

### 목표

<p>
  먼저 이 프로젝트의 1차적인 목표는 외부에서 들어오는 공격, 특히 DDoS에 대하여 인공지능을 활용하여 방어할 수 있도록 구성하는 것이었다. </br>
  우선 딥러닝 학습을 통해 정상적인 네트워크 흐름에 대해 다음 값을 예측하도록 하고, 예측한 값에서 크게 벗어났을 때 이를 공격이라 간주하게 한다. </br>
  그리고 이러한 패킷이 전송된 IP를 방화벽 도구를 이용하여 자동으로 차단하고 추가적인 공격을 방어할 수 있게 하는 것이 목표였다. </br>
  여기서 더 나아가 위에서 서술하였던 자동 IP 차단 이외에도 수동 IP 차단/허용, Routing, NAT 그리고 VPN 기능을 구현하고, 시각화를 통한 모니터링과 각 기능의 세부 설정 조정이 가능한 웹페이지를 구성한다. </br>
  최종적으로 다양한 보안 기능을 하나의 장치나 솔루션으로 통합하여 네트워크의 보안 위협을 관리하는 시스템인 UTM을 구현하는 것을 최종 목표로 하였다.
</p>

# 👤 팀원
<table>
  <tr>
    <td>팀장</td>
    <td>김태일</td>
    <td>AI</td>
  </tr>
  <tr>
    <td>팀원</td>
    <td>이찬재</td>
    <td>Full Stack</td>
  </tr>
  <tr>
    <td>팀원</td>
    <td>허정윤</td>
    <td>Security</td>
  </tr>
</table>

<br>

# 📆 개발 기간
<ul>
  <li> <h3>24.09 ~ 24.11</h3> </li>
</ul>
</br>




# 🔧 기능
<table>
  <tr>
    <td>Login</td>
    <td> <img width= "689" alt="Login" src=https://github.com/user-attachments/assets/0af8fbf0-410d-41b4-bcd6-8b2e7c15bb89></td>
  </tr>
  <tr>
    <td>DashBoard</td>
    <td><img width= "689" alt="DashBoard" src=https://github.com/user-attachments/assets/5579ae8a-2e0d-49a4-a3df-a363731964a9></td> 
</td>
  </tr>
  <tr>
    <td>Ip Controller</td>
    <td><img width= "689" alt="IP Controller" src=https://github.com/user-attachments/assets/bc11c598-a3cf-46a2-9cef-ceef6193f1fa></td>
  </tr>
</table>

<table>
  <tr>
    <td>AI Controller</td>
    <td><img width= "689" alt="AI Controller" src=https://github.com/user-attachments/assets/fa5bf50e-ba0c-4cf7-9ebb-2eeee25a05c9></td>
  </tr>
  <tr>
    <td>NAT</td>
    <td>
      <img width= "689" alt="NAT1" src=https://github.com/user-attachments/assets/1d79d5a2-3de1-44b7-9867-d9b8d471b2a5>
      <img width= "689" alt="NAT2" src=https://github.com/user-attachments/assets/68bfca90-d724-4978-a5d3-c4c1b5d390b1>
    </td>
  </tr>
  <tr>
    <td>Static Routing</td>
    <td>
      <img width= "689" alt="Static Routing" src=https://github.com/user-attachments/assets/bfa06ff4-e00e-4514-aae1-ba0e82b9a900>
    </td>
  </tr>
</table>

<table>
   <tr>
    <td>BGP</td>
    <td>
      <img width= "689" alt="BGP" src=https://github.com/user-attachments/assets/4e205d4e-a6ff-4c45-9e48-674e293ac14e>
    </td>
  </tr>
  <tr>
    <td>VPN</td>
    <td>
      <img width= "689" alt="VPN" src=https://github.com/user-attachments/assets/5b28682e-8f22-4ba9-ba01-4ec62562c29c>
    </td>
  </tr>
  <tr>
    <td>Interface </br> Management</td>
    <td>
      <img width= "689" alt="VPN" src=https://github.com/user-attachments/assets/3c63f54a-46f6-4ef3-adb1-1c921888eaff>
    </td>
  </tr>
  <tr>
    <td>User </br> Interface</td>
      <td><img width= "689" alt="User Interface" src=https://github.com/user-attachments/assets/f2f7abaf-bf9c-456c-8863-a282762ba327></td>
  </tr>
</table>


# 🛠️ 구성도
<div>  
  <ul>
    <li> 네트워크 구조</li>
    <img  alt="Network structure" src=https://github.com/user-attachments/assets/1f89e5ce-0d7a-4d0b-9968-88fc79751914>
    <img  width= "389" alt="Network structure" src=https://github.com/user-attachments/assets/dfd2302e-83d1-4bc7-916b-0f12dd6a5917>
    <li> 디렉터리 구성도</li>
    <img  alt="User Interface" src=https://github.com/user-attachments/assets/ffb80677-7683-4019-bb55-47f140bc393b>
  </ul>
</div>

</br>

# 📚 기술 스택
<div align=left> 
  <img src="https://img.shields.io/badge/python-3776AB?style=for-the-badge&logo=python&logoColor=white"> 
  <img src="https://img.shields.io/badge/html5-E34F26?style=for-the-badge&logo=html5&logoColor=white"> 
  <img src="https://img.shields.io/badge/css-1572B6?style=for-the-badge&logo=css3&logoColor=white">
  </br>

  <img src="https://img.shields.io/badge/javascript-F7DF1E?style=for-the-badge&logo=javascript&logoColor=black"> 
  <img src="https://img.shields.io/badge/openvpn-EA7E20?style=for-the-badge&logo=openvpn&logoColor=white"> 
  <img src="https://img.shields.io/badge/linux-FCC624?style=for-the-badge&logo=linux&logoColor=white"> 
  </br>
  
  <img src="https://img.shields.io/badge/github-181717?style=for-the-badge&logo=github&logoColor=white"> 
  <img src="https://img.shields.io/badge/Flask-000000?style=for-the-badge&logo=Flask&logoColor=white"> 
  <img src="https://img.shields.io/badge/bootstrap-7952B3?style=for-the-badge&logo=bootstrap&logoColor=white">
  <img src="https://img.shields.io/badge/nvidia-76B900?style=for-the-badge&logo=nvidia&logoColor=white">
  </br>

  <img src="https://img.shields.io/badge/pandas-150458?style=for-the-badge&logo=pandas&logoColor=white">
  <img src="https://img.shields.io/badge/pytorch-EE4C2C?style=for-the-badge&logo=pytorch&logoColor=white">

</div>

