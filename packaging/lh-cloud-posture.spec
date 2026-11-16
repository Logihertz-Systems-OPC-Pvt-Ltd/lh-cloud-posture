Name:           lh-cloud-posture
Version:        0.1.0
Release:        1%{?dist}
Summary:        lh-cloud - Cloud Security Posture Scoring & IAM Entitlement Matrix
License:        Apache-2.0
URL:            https://github.com/Logihertz-Systems-OPC-Pvt-Ltd/lh-cloud-posture
Source0:        %{name}-%{version}-src.tar.gz
Packager:       Sameer Tawade <ops@logihertz.com>
BuildArch:      noarch

%description
Multi-cloud Infrastructure-as-Code (IaC) security posture auditor scanning Terraform, Kubernetes, and CloudFormation manifests for IAM privilege escalation, public storage, and CIS benchmark risks.

%prep
%autosetup -n %{name}-0.1.0

%build
# Industrial clean-room build with zero external runtime dependencies

%install
rm -rf %{buildroot}
mkdir -p %{buildroot}%{_bindir}
mkdir -p %{buildroot}%{_docdir}/%{name}
mkdir -p %{buildroot}%{_mandir}/man1

if [ -f bin/lh-cloud ]; then
    install -m 0755 bin/lh-cloud %{buildroot}%{_bindir}/lh-cloud
elif [ -f lh-cloud ]; then
    install -m 0755 lh-cloud %{buildroot}%{_bindir}/lh-cloud
fi

install -m 0644 README.md %{buildroot}%{_docdir}/%{name}/README.md
install -m 0644 SPEC.md %{buildroot}%{_docdir}/%{name}/SPEC.md
install -m 0644 LICENSE %{buildroot}%{_docdir}/%{name}/LICENSE
install -m 0644 NOTICE %{buildroot}%{_docdir}/%{name}/NOTICE

%files
%doc %{_docdir}/%{name}/README.md
%doc %{_docdir}/%{name}/SPEC.md
%doc %{_docdir}/%{name}/NOTICE
%license %{_docdir}/%{name}/LICENSE

%changelog
* Mon Nov 16 2026 Sameer Tawade <ops@logihertz.com> - 0.1.0-1
- Initial production release for Logihertz Systems Ecosystem and STRUCT OS.
