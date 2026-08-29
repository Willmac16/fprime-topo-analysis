// Named ...BaseStub rather than ...Ac because the repository ignores *Ac.*
// as autocode. The extractor keys on the ComponentBase class name, not the file.
// Stands in for FPP-generated component base code. Only the shapes the call
// graph extractor keys on matter: <port>_out invokers, generated helpers, and
// m_<port>_OutputPort members.
#ifndef TEST_COMPONENT_AC_HPP
#define TEST_COMPONENT_AC_HPP

namespace Svc {

class TestThingComponentBase {
  public:
    struct OutputPort {
        void invoke(int arg);
    };

  protected:
    virtual void gIn_handler(int portNum) = 0;
    virtual void sIn_handler(int portNum) = 0;
    virtual void NOOP_cmdHandler(int opCode) = 0;

    void alphaOut_out(int portNum, int arg);
    void betaOut_out(int portNum, int arg);
    void tlmWrite_Count(int value);
    void log_WARNING_HI_Trouble(int code);

    OutputPort m_alphaOut_OutputPort[1];
    OutputPort m_betaOut_OutputPort[1];
    OutputPort m_tlmOut_OutputPort[1];
    OutputPort m_eventOut_OutputPort[1];
};

}  // namespace Svc

#endif
