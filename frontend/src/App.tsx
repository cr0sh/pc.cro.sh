import { Button, Container, Grid, TextField, ThemeProvider, Typography, Stack, Tooltip, createTheme, styled } from '@mui/material';
import React from 'react';
import './App.css';
import { deepOrange, lightBlue, orange, red, yellow } from '@mui/material/colors';
import { GoogleReCaptchaProvider, IGoogleReCaptchaConsumerProps, useGoogleReCaptcha } from 'react-google-recaptcha-v3';

interface IInputFileProps {
  files: File[],
}

interface WasmProps {
  wasm: WasmType,
}

const theme = createTheme({
  palette: {
    primary: {
      main: deepOrange[500],
    },
    secondary: {
      main: orange[200],
    },
    error: {
      main: red[700],
    },
    warning: {
      main: yellow[400],
    },
    info: {
      main: lightBlue[400],
    }
  },
});

const Input = styled('input')({
  display: 'none',
});

const WrappedButton: React.FC<IInputFileProps & React.ComponentProps<typeof Button>> = ({ files, children, ...props }) => {
  if (files.length === 0) {
    return (<Tooltip title={<div className="tooltip-text">레지스트리 파일을 선택하세요</div>} followCursor>
      <span>
        <Button {...props} disabled>
          <>{children}</>
        </Button>
      </span>
    </Tooltip>);
  }

  return (
    <Button {...props}>
      <>{children}</>
    </Button>
  );
}

const Title: React.FC = () => (
  <Container className="app-title">
    <Typography variant="h2">메이플스토리 설정 연동<div className="beta-sup"><i>beta</i></div></Typography>
  </Container>
);

const UploadForm: React.FC<IGoogleReCaptchaConsumerProps & WasmProps> = ({ executeRecaptcha, wasm }) => {
  interface IFormValidation {
    name: string | undefined,
    password: string | undefined,
  };

  const [files, setFiles] = React.useState<File[]>([]);
  const [validation, setValidation] = React.useState<IFormValidation>({ name: undefined, password: undefined });
  const nameRef = React.useRef<HTMLInputElement>(null);
  const passwordRef = React.useRef<HTMLInputElement>(null);
  const passwordCheckRef = React.useRef<HTMLInputElement>(null);

  const onClick = React.useCallback(async () => {
    if (executeRecaptcha === undefined) {
      return;
    }

    const v: IFormValidation = {
      name: undefined,
      password: undefined
    };

    try {
      console.log(nameRef.current?.value);
      if ((nameRef.current?.value.length || 0) < 3) {
        v.name = "3글자 이상이어야 합니다.";
      }

      if ((passwordRef.current?.value || "") !== (passwordCheckRef.current?.value || "")) {
        v.password = "두 비밀번호가 다릅니다.";
        return;
      }

      if ((passwordRef.current?.value.length || 0) < 6) {
        v.password = "비밀번호는 6글자 이상이어야 합니다."
      }
    } finally {
      setValidation(v);
    }

    if (!!v.name || !!v.password) {
      return;
    }

    const token = await executeRecaptcha();
    const buffer = await files[0].arrayBuffer();
    wasm!!.store_put(new Uint8Array(buffer), nameRef.current!!.value, passwordRef.current!!.value, token);
  }, [executeRecaptcha, files, wasm]);

  const onFileChange = React.useCallback((ev: React.ChangeEvent<HTMLInputElement>) => {
    const f = ev.target.files;
    if (f === null) {
      return;
    }

    setFiles([f[0]]);
  }, []);

  return (
    <Stack className="id-pw-input" spacing={2} width="md">
      <Typography variant="h5">설정 업로드</Typography>
      <TextField label="이름" variant="filled" error={!!validation.name} helperText={validation.name} inputRef={nameRef}></TextField>
      <TextField label="비밀번호" variant="outlined" type="password" error={!!validation.password} helperText={validation.password} inputRef={passwordRef}></TextField>
      <TextField label="비밀번호(확인)" variant="outlined" type="password" error={!!validation.password} helperText={validation.password} inputRef={passwordCheckRef}></TextField>
      <Grid container justifyContent="space-between">
        <label htmlFor="file-selector-button">
          <Input accept="text/*" type="file" id="file-selector-button" onChange={onFileChange} />
          <Button variant="contained" color="primary" component="span">.reg 파일 선택</Button>
        </label>
        <WrappedButton variant="contained" color="primary" disabled={!executeRecaptcha || !wasm} files={files} onClick={onClick}>설정 업로드</WrappedButton>
      </Grid>
    </Stack>
  );
}

const DownloadForm: React.FC<IGoogleReCaptchaConsumerProps & WasmProps> = ({ executeRecaptcha, wasm }) => {

  return (
    <Stack className="id-pw-input" spacing={2} width="sm">
      <Typography variant="h5">설정 다운로드</Typography>
      <TextField label="이름" variant="filled"></TextField>
      <TextField label="비밀번호" variant="outlined" type="password"></TextField>
      <Grid container justifyContent="flex-end">
        <Button variant="contained" color="primary" disabled={!executeRecaptcha || !wasm}>설정 다운로드</Button>
      </Grid>
    </Stack>
  )
}

type WasmType = typeof import("./pkg") | undefined;
const Forms: React.FC = () => {
  const [wasm, setWasm] = React.useState<WasmType | undefined>(undefined);
  React.useEffect(() => {
    const fetchWasm = async () => {
      const wasm = await import("./pkg");
      setWasm(wasm);
    };
    fetchWasm();
  }, []);
  const { executeRecaptcha } = useGoogleReCaptcha();

  return (
    <Container maxWidth="lg" style={{ "padding": "3em" }}>
      <Stack className="forms-container" direction="row" spacing={3} justifyContent="center">
        <UploadForm executeRecaptcha={executeRecaptcha} wasm={wasm} />
        <DownloadForm executeRecaptcha={executeRecaptcha} wasm={wasm} />
      </Stack>
    </Container>
  );
}

const disclaimer_text: string =
  `이 서비스는 베타 버전으로 예고 없이 중지되거나 데이터가 유실될 수 있습니다.
   설정 파일은 업로드 후 1년간 보존되며 주어진 비밀번호를 사용해 암호화되어 저장됩니다.
   설정 파일에는 계정에 관련된 민감한 정보가 있을 수 있으므로 복잡한 비밀번호를 사용해야 합니다.
   유추하기 쉬운 이름(ex: abc)을 사용하면 다른 사람이 동일한 이름으로 설정 파일을 업로드해 덮어씌울 수 있습니다. 이 경우 이전 사람이 업로드한 파일은 삭제되고 비밀번호도 같이 덮어씌워집니다.
`;

const Disclaimer: React.FC = () => (
  <Container style={{ "marginTop": "4em" }} maxWidth="sm">
    <Stack spacing={2} justifyContent="left">
      <Typography variant="h4" style={{ "margin": "1em" }}>추가 정보</Typography>
      {
        disclaimer_text.trim().split(/\n\s+/).map((s, i) => (
          <Typography variant="body1" align="left" key={i}>
            {`${i}. ` + s}
          </Typography>
        ))
      }
    </Stack>
  </Container>
);


const Main: React.FC = () => {
  return (
    <GoogleReCaptchaProvider reCaptchaKey={process.env.REACT_APP_RECAPTCHA_KEY} language="ko">
      <ThemeProvider theme={theme}>
        <Title />
        <Forms />
        <Disclaimer />
      </ThemeProvider>
    </GoogleReCaptchaProvider>
  );
}

function App() {
  return (
    <div className="App">
      <Main />
    </div>
  );
}

export default App;